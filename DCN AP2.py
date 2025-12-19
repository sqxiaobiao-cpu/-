import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Toplevel
import threading
import paramiko
import time
import re
import queue
import datetime
import csv
import os
from concurrent.futures import ThreadPoolExecutor

# ================= 全局配置 =================
TARGET_AP_PASSWORDS = ["wifi_debug", "admin123"]
TARGET_AP_USER = "admin"
# ===========================================

class InteractiveConfigurator:
    def __init__(self, target_ip, wifi_configs, wired_map, rename_conf, pass_conf, country_conf, use_jump, jump_conf, update_callback, stop_event):
        self.ip = target_ip
        self.wifi_configs = wifi_configs
        self.wired_map = wired_map 
        self.rename_conf = rename_conf
        self.pass_conf = pass_conf
        self.country_conf = country_conf
        self.use_jump = use_jump
        self.jump_conf = jump_conf
        self.update_callback = update_callback
        self.stop_event = stop_event
        self.client = None
        self.shell = None
        self.interaction_log = []
        self.start_time = None
        
        # 修复语法：分行写
        if not os.path.exists("logs"): 
            try:
                os.makedirs("logs")
            except:
                pass
        self.log_file = f"logs/ap_{self.ip}_{int(time.time())}.txt"

    def _log_interaction(self, data, direction="RX"):
        ts = datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]
        log_line = ""
        if direction == "TX":
            log_line = f"[{ts}] [SEND] {data.strip()}"
        elif direction == "SYS":
            log_line = f"[{ts}] [系统] {data}"
        else:
            clean = re.sub(r'\x1b\[[0-9;]*m', '', data).replace('\r', '')
            if clean.strip():
                log_line = f"[{ts}] [RECV] {clean}"
        
        if log_line:
            self.interaction_log.append(log_line)
            # 修复语法：分行写
            try:
                with open(self.log_file, "a", encoding="utf-8") as f:
                    f.write(log_line + "\n")
            except:
                pass

    def _read_until(self, patterns, timeout=10):
        buffer = ""
        start = time.time()
        while time.time() - start < timeout:
            if self.stop_event.is_set():
                return "", -1
            if self.shell.recv_ready():
                try:
                    chunk = self.shell.recv(8192).decode('utf-8', errors='ignore')
                    self._log_interaction(chunk, "RX")
                    buffer += chunk
                    if "More" in chunk or "--More--" in chunk:
                        self.shell.send(" ")
                    clean = re.sub(r'\x1b\[[0-9;]*m', '', buffer)
                    for idx, pat in enumerate(patterns):
                        if re.search(pat, clean, re.IGNORECASE):
                            return buffer, idx
                except:
                    break
            else:
                time.sleep(0.05)
        return buffer, -1

    def _send(self, cmd):
        self.shell.send(cmd)
        self._log_interaction(cmd, "TX")

    def run(self):
        self.start_time = time.time()
        self.update_callback(self.ip, "进行中", "初始化...", None)
        try:
            connected = False
            if self.use_jump:
                if self._connect_jump_host() and self._jump_to_target_robust():
                    connected = True
            else:
                if self._connect_direct():
                    connected = True
            
            if not connected:
                return

            curr_mac = None
            if self.rename_conf['enable']:
                self.update_callback(self.ip, "进行中", "查询MAC...", None)
                curr_mac = self._get_device_mac()
                if curr_mac == "UNKNOWN":
                    self.update_callback(self.ip, "失败", "MAC获取失败", self._get_full_log())
                    return

            self.update_callback(self.ip, "进行中", "下发配置...", None)
            cmds, actions = self._generate_commands(curr_mac)
            
            for cmd in cmds:
                if self.stop_event.is_set():
                    break
                self._send(cmd + "\n")
                if "network restart" in cmd or "passwd" in cmd:
                    time.sleep(2.0)
                else:
                    self._read_until([r"~#", r"@Yunke", r"China", r"root@"], timeout=2)

            self._send("exit\n")
            time.sleep(0.5)
            duration = f"{time.time() - self.start_time:.1f}s"
            self.update_callback(self.ip, "成功", f"{actions} ({duration})", self._get_full_log())
        except Exception as e:
            self.update_callback(self.ip, "失败", f"异常: {str(e)}", self._get_full_log())
        finally:
            # 修复语法错误的地方：必须分行
            if self.client:
                try:
                    self.client.close()
                except:
                    pass

    def _get_full_log(self):
        return "\n".join(self.interaction_log)

    def _connect_direct(self):
        self.client = paramiko.SSHClient()
        self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        for pwd in TARGET_AP_PASSWORDS:
            try:
                self.client.connect(self.ip, username=TARGET_AP_USER, password=pwd, timeout=5, allow_agent=False, look_for_keys=False)
                self.shell = self.client.invoke_shell()
                self._read_until([r"~#", r"@Yunke", r"China", r"root@"], timeout=5)
                return True
            except:
                continue
        self.update_callback(self.ip, "失败", "直连密码错误", self._get_full_log())
        return False

    def _connect_jump_host(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.client.connect(self.jump_conf['ip'], username=self.jump_conf['user'], password=self.jump_conf['pass'], timeout=10, allow_agent=False, look_for_keys=False)
            self.shell = self.client.invoke_shell()
            self._read_until([r'[#>]'], timeout=5)
            return True
        except Exception as e:
            self.update_callback(self.ip, "失败", f"跳板机Err: {e}", self._get_full_log())
            return False

    def _jump_to_target_robust(self):
        pats = [r"password:", r"\(yes/no\)\?", r"refused", r"timed out", r"no route", r"denied", r"unreachable", r"~#", r"@Yunke", r"China", r"root@"]
        for i, pwd in enumerate(TARGET_AP_PASSWORDS):
            self.shell.send("\x03")
            time.sleep(0.5)
            self._send("\n")
            self._send(f"ssh {TARGET_AP_USER} {self.ip}\n")
            start = time.time()
            while time.time() - start < 15:
                buf, idx = self._read_until(pats, timeout=5)
                if idx == -1:
                    break 
                if idx == 1:
                    self._send("yes\n")
                    continue
                if idx == 0: 
                    self._send(f"{pwd}\n")
                    _, l_idx = self._read_until([r"~#", r"@Yunke", r"China", r"password:", r"denied", r"closed"], timeout=8)
                    if l_idx in [0, 1, 2]:
                        self._log_interaction(">>> 登录成功！", "SYS")
                        return True
                    else:
                        break
                if idx in [7, 8, 9, 10]:
                    return True
                if idx in [2, 3, 4, 5, 6]: 
                    self.update_callback(self.ip, "失败", f"SSH连通性错误: {buf.strip()}", self._get_full_log())
                    return False
        self.update_callback(self.ip, "失败", "所有密码尝试失败", self._get_full_log())
        return False

    def _get_device_mac(self):
        self._send("get-system detail\n")
        out, _ = self._read_until([r"~#", r"@Yunke", r"China"], timeout=5)
        m = re.search(r"base-mac\s+([0-9a-fA-F:.-]+)", out, re.IGNORECASE)
        return re.sub(r"[^a-fA-F0-9]", "", m.group(1)).upper() if m else "UNKNOWN"

    def _generate_commands(self, current_mac):
        cmds = []
        act = []

        # 1. 改名
        if self.rename_conf['enable']:
            if current_mac in self.rename_conf['map']:
                nn = self.rename_conf['map'][current_mac]
                cmds.append(f"uci set system.@system[0].hostname='{nn}'")
                act.append(f"改名[{nn}]")
            else:
                act.append("MAC未匹配")

        # 2. 改密
        if self.pass_conf['enable']:
            p = self.pass_conf['new_pass']
            cmds.append(f"printf '{p}\\n{p}\\n' | passwd {TARGET_AP_USER}")
            act.append("改密")

        # 3. 业务配置
        self._send("uci show wireless\n")
        raw = ""
        while True:
            chunk, idx = self._read_until([r"~#", r"@Yunke", r"China"], timeout=1)
            raw += chunk
            if idx != -1:
                break
        raw = re.sub(r'\x1b\[[0-9;]*m', '', raw)

        # 侦测射频
        detected_radios = set()
        if "wireless.wifi0" in raw: detected_radios.add("wifi0")
        if "wireless.wifi1" in raw: detected_radios.add("wifi1")
        if not detected_radios: detected_radios = {"wifi0", "wifi1"}

        # 国家码
        if self.country_conf['enable']:
            cc = self.country_conf['code']
            for dev in detected_radios:
                cmds.append(f"uci set wireless.{dev}.country='{cc}'")
            act.append(f"国家码[{cc}]")

        # 匹配旧 SSID
        keyword = self.wifi_configs[0]['keyword'] 
        old_indices = []
        p_idx = r"(wireless\.@wifi-iface\[\d+\])\.ssid=.*" + re.escape(keyword)
        for line in raw.splitlines():
            if re.search(p_idx, line, re.IGNORECASE):
                old_indices.append(line.split(".")[1])

        # 多 SSID 逻辑
        start_index = 0
        if not old_indices:
            act.append(f"强制新增SSID")
        else:
            act.append(f"覆盖旧SSID")
            first_conf = self.wifi_configs[0]
            for idx_str in old_indices:
                cmds.append(self._build_uci_set(idx_str, first_conf))
            start_index = 1

        if len(self.wifi_configs) > start_index:
            added_count = 0
            for dev in detected_radios:
                for i in range(start_index, len(self.wifi_configs)):
                    conf = self.wifi_configs[i]
                    cmds.append("uci add wireless wifi-iface")
                    base = "@wifi-iface[-1]"
                    cmds.append(f"uci set wireless.{base}.device='{dev}'")
                    cmds.append(f"uci set wireless.{base}.mode='ap'")
                    cmds.append(self._build_uci_set(base, conf))
                    added_count += 1
            act.append(f"新增VAP({added_count})")

        # 网络底层 (VLAN Bridge)
        needed_vlans = set()
        for c in self.wifi_configs:
            if c['vlan'] != '1':
                needed_vlans.add(c['vlan'])
        for vlan in needed_vlans:
            n = f"vlan{vlan}"
            cmds.append(f"uci set network.{n}=interface")
            cmds.append(f"uci set network.{n}.type='bridge'")
            cmds.append(f"uci set network.{n}.proto='none'")
            cmds.append(f"uci set network.{n}.ifname='eth0.{vlan}'")

        # === 4. 有线口 (新逻辑：仅配置勾选端口) ===
        wired_configured_count = 0
        for p, info in self.wired_map.items():
            if info['enable']:
                cmds.append(f"uci set lanport.{p}.vlan='{info['vlan']}'")
                cmds.append(f"uci set lanport.{p}.state='enable'")
                wired_configured_count += 1
            # else: 不做任何操作，保留原配置
        
        if wired_configured_count > 0:
            act.append(f"配置有线口({wired_configured_count})")

        cmds.append("uci commit")
        cmds.append("/etc/init.d/network restart")
        return cmds, "+".join(act)

    def _build_uci_set(self, base, conf):
        c = []
        prefix = f"uci set wireless.{base}"
        c.append(f"{prefix}.ssid='{conf['ssid']}'")
        c.append(f"{prefix}.encryption='{conf['encrypt']}'")
        c.append(f"{prefix}.key='{conf['key']}'")
        c.append(f"{prefix}.vlan='{conf['vlan']}'")
        c.append(f"{prefix}.isolate='{conf['isolate']}'")
        hidden_val = conf.get('hidden', '0')
        c.append(f"{prefix}.hidden='{hidden_val}'") 
        c.append(f"{prefix}.enabled='1'")
        return "\n".join(c)

class SsidDialog:
    def __init__(self, parent, callback):
        self.win = Toplevel(parent)
        self.win.title("配置 SSID / 选择模版")
        self.win.geometry("350x380")
        self.callback = callback
        self.result = None
        
        self.templates = {
            "自定义 (Custom)": {"ssid":"", "vlan":"1", "hidden":"0"},
            "IHG Studio": {"ssid":"IHG Studio", "vlan":"2012", "hidden":"1"},
            "IHG Speaker": {"ssid":"IHG Speaker", "vlan":"1800", "hidden":"1"},
            "IHG Laundry": {"ssid":"IHG Laundry", "vlan":"220", "hidden":"1"},
            "IHG POS": {"ssid":"IHG POS", "vlan":"240", "hidden":"1"},
            "IHG RCU": {"ssid":"IHG RCU", "vlan":"250", "hidden":"1"},
        }

        f_tmpl = ttk.Frame(self.win); f_tmpl.pack(pady=10, fill="x", padx=20)
        ttk.Label(f_tmpl, text="快速模版:").pack(side="left")
        self.cb_tmpl = ttk.Combobox(f_tmpl, values=list(self.templates.keys()), state="readonly")
        self.cb_tmpl.pack(side="left", fill="x", expand=True, padx=5)
        self.cb_tmpl.bind("<<ComboboxSelected>>", self.on_template_change)
        self.cb_tmpl.current(0)

        ttk.Label(self.win, text="SSID 名称:").pack(pady=(5,0))
        self.e_ssid = ttk.Entry(self.win, width=35); self.e_ssid.pack()

        ttk.Label(self.win, text="VLAN ID:").pack(pady=(5,0))
        self.e_vlan = ttk.Entry(self.win, width=10); self.e_vlan.pack()

        f_enc = ttk.Frame(self.win); f_enc.pack(pady=5)
        ttk.Label(f_enc, text="加密:").pack(side="left")
        self.cb_enc = ttk.Combobox(f_enc, values=["none", "psk2"], width=8, state="readonly")
        self.cb_enc.pack(side="left"); self.cb_enc.current(1)
        
        ttk.Label(self.win, text="密码 (请自定义):").pack(pady=(5,0))
        self.e_key = ttk.Entry(self.win, width=35); self.e_key.pack()

        f_opts = ttk.Frame(self.win); f_opts.pack(pady=10)
        self.v_iso = tk.IntVar(value=1)
        ttk.Checkbutton(f_opts, text="用户隔离", variable=self.v_iso).pack(side="left", padx=5)
        self.v_hide = tk.IntVar(value=0)
        ttk.Checkbutton(f_opts, text="隐藏SSID", variable=self.v_hide).pack(side="left", padx=5)

        ttk.Button(self.win, text="确定", command=self.on_ok).pack(pady=10)

    def on_template_change(self, event):
        tmpl_name = self.cb_tmpl.get()
        data = self.templates.get(tmpl_name)
        if data:
            self.e_ssid.delete(0, tk.END); self.e_ssid.insert(0, data["ssid"])
            self.e_vlan.delete(0, tk.END); self.e_vlan.insert(0, data["vlan"])
            self.v_hide.set(int(data["hidden"]))

    def on_ok(self):
        if not self.e_ssid.get(): return
        self.result = {
            'ssid': self.e_ssid.get(),
            'vlan': self.e_vlan.get(),
            'encrypt': self.cb_enc.get(),
            'key': self.e_key.get(),
            'isolate': str(self.v_iso.get()),
            'hidden': str(self.v_hide.get())
        }
        self.callback(self.result)
        self.win.destroy()

class ConfigApp:
    def __init__(self, root):
        self.root = root; self.root.title("神州云科 AP 终极配置 (Wired+Templates)"); self.root.geometry("1280x850")
        self.msg_queue = queue.Queue(); self.stop_event = threading.Event(); self.is_running = False
        self.detail_logs = {}; self.mac_host_map = {}; self.ssid_configs = [] 
        self._init_ui(); self._check_queue()

    def _init_ui(self):
        paned = tk.PanedWindow(self.root, orient=tk.HORIZONTAL); paned.pack(fill=tk.BOTH, expand=True)
        left = ttk.Frame(paned, width=450, padding="10"); paned.add(left)
        
        # 1. 跳板机
        jh_f = ttk.LabelFrame(left, text="1. 连接模式"); jh_f.pack(fill="x", pady=5)
        self.use_jh = tk.BooleanVar(value=True); ttk.Checkbutton(jh_f, text="启用跳板机", variable=self.use_jh, command=self._upd_jh).pack(anchor="w")
        f1 = ttk.Frame(jh_f); f1.pack(fill="x", padx=5)
        ttk.Label(f1, text="IP:").grid(row=0,column=0); self.e_jip=ttk.Entry(f1,width=15); self.e_jip.grid(row=0,column=1)
        ttk.Label(f1, text="用户:").grid(row=1,column=0); self.e_ju=ttk.Entry(f1,width=15); self.e_ju.insert(0,"admin"); self.e_ju.grid(row=1,column=1)
        ttk.Label(f1, text="密码:").grid(row=2,column=0); self.e_jp=ttk.Entry(f1,width=15,show="*"); self.e_jp.grid(row=2,column=1)
        self.jh_ws=[self.e_jip, self.e_ju, self.e_jp]

        # 2. 无线配置
        wifi_f = ttk.LabelFrame(left, text="2. 无线配置 (Multi-SSID)"); wifi_f.pack(fill="x", pady=5)
        
        f_rep = ttk.Frame(wifi_f); f_rep.pack(fill="x", pady=2)
        self.c_rep = tk.BooleanVar(value=True)
        ttk.Checkbutton(f_rep, text="覆盖旧SSID (关键词):", variable=self.c_rep, command=self._upd_wifi).pack(side="left")
        self.e_kw = ttk.Entry(f_rep, width=12); self.e_kw.insert(0, "DCYK"); self.e_kw.pack(side="left", padx=5)

        f_add = ttk.Frame(wifi_f); f_add.pack(fill="x", pady=2)
        self.c_add = tk.BooleanVar(value=True)
        ttk.Checkbutton(f_add, text="新增 SSID (列表)", variable=self.c_add).pack(side="left")

        f_cc = ttk.Frame(wifi_f); f_cc.pack(fill="x", pady=2)
        self.c_cc = tk.BooleanVar(value=True)
        ttk.Checkbutton(f_cc, text="设置国家码:", variable=self.c_cc).pack(side="left")
        self.e_cc = ttk.Entry(f_cc, width=5); self.e_cc.insert(0, "CN"); self.e_cc.pack(side="left", padx=5)

        self.ssid_list = tk.Listbox(wifi_f, height=6); self.ssid_list.pack(fill="x", padx=5, pady=2)
        btn_f = ttk.Frame(wifi_f); btn_f.pack(fill="x", padx=5, pady=5)
        ttk.Button(btn_f, text="➕ 添加 SSID", command=lambda:SsidDialog(self.root, self.add_ssid)).pack(side="left", fill="x", expand=True)
        ttk.Button(btn_f, text="➖ 删除", command=self.del_ssid).pack(side="left", fill="x", expand=True, padx=5)
        ttk.Button(btn_f, text="🔄 清空", command=self.clr_ssid).pack(side="left", fill="x", expand=True)
        
        self.add_ssid({'ssid': 'IHG ONE REWARDS Free WI-FI', 'vlan': '1000', 'encrypt': 'none', 'key': '', 'isolate': '1', 'hidden': '0'})

        # 3. 有线 (改为勾选模式)
        wf2 = ttk.LabelFrame(left, text="3. 有线端口 (勾选下发配置，未勾选保持原状)"); wf2.pack(fill="x", pady=5)
        self.w_vars = {} 
        self.w_ents = {} 
        
        for i in range(1, 5):
            row = (i-1) // 2
            col = (i-1) % 2
            f = ttk.Frame(wf2); f.grid(row=row, column=col, padx=5, pady=2, sticky="w")
            
            var = tk.BooleanVar(value=False)
            self.w_vars[f"lan{i}"] = var
            ttk.Checkbutton(f, text=f"LAN{i}", variable=var, command=lambda k=f"lan{i}": self._upd_lan(k)).pack(side="left")
            
            e = ttk.Entry(f, width=4, justify="center"); e.insert(0, "1"); e.pack(side="left", padx=2)
            e.config(state="disabled")
            self.w_ents[f"lan{i}"] = e

        # 4. 维护
        mt_f = ttk.LabelFrame(left, text="4. 维护 (可选)"); mt_f.pack(fill="x", pady=5)
        self.c_rn = tk.BooleanVar(); ttk.Checkbutton(mt_f, text="改名 (CSV)", variable=self.c_rn, command=self._upd_mt).pack(anchor="w")
        self.b_csv = ttk.Button(mt_f, text="导入 MAC 表", command=self.load_csv, state="disabled"); self.b_csv.pack(fill="x")
        self.l_csv = ttk.Label(mt_f, text="未导入", foreground="gray"); self.l_csv.pack(anchor="w")
        self.c_pw = tk.BooleanVar(); ttk.Checkbutton(mt_f, text="改密", variable=self.c_pw, command=self._upd_mt).pack(anchor="w")
        self.e_np=ttk.Entry(mt_f,width=12,state="disabled"); self.e_np.pack(fill="x")

        # 5. IP
        ip_f = ttk.LabelFrame(left, text="5. 目标 IP"); ip_f.pack(fill="both", expand=True, pady=5)
        self.t_ip = tk.Text(ip_f, height=5, width=30); self.t_ip.pack(fill="both", expand=True)
        self.t_ip.insert(tk.END, "192.168.1.10\n192.168.1.11")
        self.b_go = ttk.Button(left, text="▶ 执行全量配置", command=self.start); self.b_go.pack(fill="x", pady=5)

        # Right
        right = ttk.Frame(paned, padding="10"); paned.add(right)
        sf = ttk.Frame(right); sf.pack(fill="x")
        self.pg = ttk.Progressbar(sf, mode="determinate"); self.pg.pack(side="left", fill="x", expand=True)
        self.l_st = ttk.Label(sf, text="就绪"); self.l_st.pack(side="right")
        tf = ttk.Frame(right); tf.pack(fill="both", expand=True, pady=5)
        self.tr = ttk.Treeview(tf, columns=("ip","st","tm","inf"), show="headings")
        self.tr.heading("ip", text="IP"); self.tr.column("ip", width=120)
        self.tr.heading("st", text="状态"); self.tr.column("st", width=60, anchor="center")
        self.tr.heading("tm", text="时间"); self.tr.column("tm", width=80, anchor="center")
        self.tr.heading("inf", text="详情"); self.tr.column("inf", width=450)
        sb = ttk.Scrollbar(tf, command=self.tr.yview); self.tr.configure(yscrollcommand=sb.set)
        self.tr.pack(side="left", fill="both", expand=True); sb.pack(side="right", fill="y")
        self.tr.bind("<Double-1>", self.show_log)
        self.tr.tag_configure("success", foreground="green"); self.tr.tag_configure("fail", foreground="red"); self.tr.tag_configure("running", foreground="blue")
        ttk.Button(right, text="🔍 日志", command=lambda: self.show_log(None)).pack(fill="x", pady=2)
        self.l_sys = scrolledtext.ScrolledText(right, height=5, state="disabled", font=("Consolas",8)); self.l_sys.pack(fill="x")

    def _upd_jh(self):
        s = "normal" if self.use_jh.get() else "disabled"
        for w in self.jh_ws: w.configure(state=s)
    def _upd_mt(self):
        self.b_csv.configure(state="normal" if self.c_rn.get() else "disabled")
        self.e_np.configure(state="normal" if self.c_pw.get() else "disabled")
    def _upd_wifi(self):
        self.e_kw.configure(state="normal" if self.c_rep.get() else "disabled")
    def _upd_lan(self, key):
        self.w_ents[key].configure(state="normal" if self.w_vars[key].get() else "disabled")

    def add_ssid(self, c): 
        self.ssid_configs.append(c)
        hidden_mark = " (Hidden)" if c.get('hidden') == '1' else ""
        self.ssid_list.insert(tk.END, f"{c['ssid']} (VLAN:{c['vlan']}{hidden_mark})")
    def del_ssid(self): 
        if self.ssid_list.curselection(): idx=self.ssid_list.curselection()[0]; self.ssid_list.delete(idx); self.ssid_configs.pop(idx)
    def clr_ssid(self): self.ssid_list.delete(0, tk.END); self.ssid_configs=[]
    def load_csv(self):
        p = filedialog.askopenfilename()
        if p:
            try:
                cnt=0; self.mac_host_map={}
                with open(p, 'r', encoding='utf-8') as f:
                    for r in csv.reader(f):
                        if len(r)>=2: 
                            mac=re.sub(r"[^a-fA-F0-9]", "", r[0]).upper()
                            if len(mac)==12: self.mac_host_map[mac]=r[1].strip(); cnt+=1
                self.l_csv.config(text=f"已导入 {cnt}", foreground="green")
            except Exception as e: messagebox.showerror("Err", str(e))

    def _check_queue(self):
        while not self.msg_queue.empty():
            t, d, x = self.msg_queue.get()
            if t == "sys": self.l_sys.config(state="normal"); self.l_sys.insert(tk.END, f"{d}\n"); self.l_sys.see(tk.END); self.l_sys.config(state="disabled")
            elif t == "row":
                ip, st, inf, log = d; self.detail_logs[ip] = log
                iid=None
                for c in self.tr.get_children():
                    if self.tr.item(c)["values"][0]==ip: iid=c; break
                tg="success" if st=="成功" else "fail" if st=="失败" else ""
                v=(ip,st,datetime.datetime.now().strftime("%H:%M:%S"),inf)
                if iid: self.tr.item(iid,values=v,tags=(tg,))
                else: self.tr.insert("", "end", values=v, tags=(tg,))
                dn=0; tot=len(self.ips)
                for c in self.tr.get_children(): 
                    if self.tr.item(c)["values"][1] in ["成功","失败"]: dn+=1
                self.pg["max"]=tot; self.pg["value"]=dn; self.l_st.config(text=f"{dn}/{tot}")
            elif t == "fin": self.is_running=False; self.b_go.config(state="normal"); messagebox.showinfo("OK", "完成")
        self.root.after(100, self._check_queue)

    def show_log(self, e):
        sel = self.tr.selection()
        if sel and (ip:=self.tr.item(sel[0])["values"][0]) in self.detail_logs:
            w=Toplevel(self.root); w.geometry("900x700"); st=scrolledtext.ScrolledText(w); st.pack(fill="both",expand=True)
            st.insert(tk.END, self.detail_logs[ip]); st.config(state="disabled")

    def start(self):
        if self.is_running: return
        ips = [x.strip() for x in self.t_ip.get("1.0", tk.END).splitlines() if x.strip()]
        if not ips: return
        
        wm = {
            'enable_replace': self.c_rep.get(),
            'enable_add': self.c_add.get(),
            'keyword': self.e_kw.get().strip()
        }
        
        if not wm['enable_replace'] and not wm['enable_add'] and self.ssid_configs:
            if not messagebox.askyesno("提示", "您未勾选'覆盖'或'新增'，无线配置将不会生效。\n是否继续？"): return

        jc = {'ip':self.e_jip.get(),'user':self.e_ju.get(),'pass':self.e_jp.get()}
        
        # 收集有线口配置
        lc = {}
        for k, v_ent in self.w_ents.items():
            lc[k] = {
                'enable': self.w_vars[k].get(),
                'vlan': v_ent.get().strip()
            }

        rc = {'enable':self.c_rn.get(), 'map':self.mac_host_map}
        pc = {'enable':self.c_pw.get(), 'new_pass':self.e_np.get().strip()}
        cc = {'enable':self.c_cc.get(), 'code':self.e_cc.get().strip()}
        
        self.is_running=True; self.ips=ips; self.stop_event.clear()
        self.tr.delete(*self.tr.get_children()); self.b_go.config(state="disabled")
        threading.Thread(target=self.logic, args=(ips, self.ssid_configs, wm, lc, rc, pc, cc, jc), daemon=True).start()

    def logic(self, ips, wcs, wm, lc, rc, pc, cc, jc):
        max_th = 8 if self.use_jh.get() else 30
        if self.use_jh.get():
            try:
                c=paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(jc['ip'], username=jc['user'], password=jc['pass'], timeout=5)
                s=c.invoke_shell(); time.sleep(0.5); s.send("\n\n"); time.sleep(0.5); s.send("delete ssh-known-hosts\n"); time.sleep(1); c.close()
            except: pass
        def cb(ip,s,i,l): self.msg_queue.put(("row", (ip,s,i,l), None))
        with ThreadPoolExecutor(max_workers=max_th) as ex:
            for ip in ips: ex.submit(InteractiveConfigurator(ip, wcs, wm, lc, rc, pc, cc, self.use_jh.get(), jc, cb, self.stop_event).run)
        self.msg_queue.put(("fin", None, None))

if __name__ == "__main__":
    root = tk.Tk(); app = ConfigApp(root); root.mainloop()