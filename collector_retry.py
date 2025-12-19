import csv
import ipaddress
import queue
import random
import re
import socket
import threading
import time
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor, as_completed
from tkinter import filedialog, messagebox, scrolledtext, ttk

import paramiko

# --- 全局配置 ---
DCN_USER = "admin"
DCN_PASSWORDS = ["wifi_debug", "admin123", "admin"]

# 文件锁
FILE_LOCK = threading.Lock()


# --- 兼容 Telnet (保持不变) ---
class RawTelnet:
    def __init__(self, host, timeout=5):
        self.host = host
        self.timeout = timeout
        self.sock = None

    def connect(self):
        try:
            self.sock = socket.create_connection((self.host, 23), timeout=self.timeout)
            return True
        except Exception:
            return False

    def close(self):
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass

    def read_until(self, patterns, timeout=5):
        buffer = b""
        start = time.time()
        while time.time() - start < timeout:
            try:
                self.sock.setblocking(0)
                try:
                    chunk = self.sock.recv(4096)
                    if not chunk:
                        break
                    clean = bytearray()
                    skip = 0
                    for b in chunk:
                        if skip > 0:
                            skip -= 1
                            continue
                        if b == 0xFF:
                            skip = 2
                            continue
                        clean.append(b)
                    buffer += clean
                except BlockingIOError:
                    time.sleep(0.1)
                    continue
                decoded = buffer.decode("utf-8", errors="ignore")
                for idx, pat in enumerate(patterns):
                    if re.search(pat, decoded, re.IGNORECASE):
                        return decoded, idx
            except Exception:
                break
        return buffer.decode("utf-8", errors="ignore"), -1

    def write(self, text):
        if self.sock:
            try:
                self.sock.sendall(text.encode("utf-8"))
            except Exception:
                pass


# --- 核心逻辑 ---
def parse_ip_input(input_str):
    final_ips = set()
    if not input_str or not input_str.strip():
        return final_ips
    entries = [x.strip() for x in input_str.replace("\n", ",").split(",")]
    for entry in entries:
        if not entry:
            continue
        try:
            if "-" in entry:
                parts = entry.split("-")
                s_str = parts[0].strip()
                e_str = parts[1].strip()
                s_ip = ipaddress.IPv4Address(s_str)
                if "." in e_str:
                    e_ip = ipaddress.IPv4Address(e_str)
                else:
                    e_ip = ipaddress.IPv4Address(f"{str(s_ip).rsplit('.', 1)[0]}.{e_str}")
                s = int(s_ip)
                e = int(e_ip)
                if s <= e:
                    for i in range(s, e + 1):
                        final_ips.add(str(ipaddress.IPv4Address(i)))
            elif "/" in entry:
                for h in ipaddress.IPv4Network(entry, strict=False).hosts():
                    final_ips.add(str(h))
            else:
                ipaddress.IPv4Address(entry)
                final_ips.add(entry)
        except Exception:
            pass
    return final_ips


class DcnApCollector:
    def __init__(self, target_ip, mode="local", jh_config=None, skip_ping=False, log_func=None, stop_event=None):
        self.ip = target_ip
        self.mode = mode
        self.jh_config = jh_config
        self.skip_ping = skip_ping
        self.log_func = log_func
        self.stop_event = stop_event
        self.client = None
        self.shell = None
        self.raw_log = ""

    def _log(self, msg, tag="info"):
        if self.log_func:
            self.log_func(msg, tag)

    def _should_stop(self):
        return self.stop_event and self.stop_event.is_set()

    def _drain_buffer(self):
        try:
            while self.shell.recv_ready():
                self.shell.recv(8192)
        except Exception:
            pass

    def _read_until_remote(self, patterns, timeout=10):
        buffer = ""
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._should_stop():
                return "", -1
            if self.shell and self.shell.recv_ready():
                try:
                    chunk = self.shell.recv(8192).decode("utf-8", errors="ignore")
                    buffer += chunk
                    self.raw_log += chunk
                    if "More" in chunk:
                        self.shell.send(" ")
                        time.sleep(0.1)
                    for idx, pat in enumerate(patterns):
                        if re.search(pat, buffer, re.IGNORECASE):
                            return buffer, idx
                except Exception:
                    break
            else:
                time.sleep(0.1)
        return buffer, -1

    def _connect_jump_host(self):
        for i in range(2):
            if self._should_stop():
                return False
            try:
                self.client = paramiko.SSHClient()
                self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                self.client.connect(
                    self.jh_config["ip"],
                    username=self.jh_config["user"],
                    password=self.jh_config["pass"],
                    timeout=20,
                    banner_timeout=20,
                )
                self.shell = self.client.invoke_shell()
                self._read_until_remote([r"[#>]"], timeout=10)
                return True
            except Exception:
                time.sleep(2)
                if i == 1:
                    raise
        return False

    def _parse_output(self, output):
        res = {"mac": "N/A", "sn": "N/A", "model": "N/A"}

        model_match = re.search(r"^model\s+([^\r\n]+)", output, re.MULTILINE | re.IGNORECASE)
        if model_match:
            res["model"] = model_match.group(1).strip()

        sn_match = re.search(r"serial-number\s+([^\r\n]+)", output, re.IGNORECASE)
        if sn_match:
            res["sn"] = sn_match.group(1).strip()

        mac_match = re.search(r"base-mac\s+([0-9a-fA-F:]{10,})", output, re.IGNORECASE)
        if mac_match:
            res["mac"] = mac_match.group(1).strip()

        if res["mac"] == "N/A":
            mac_candidates = re.findall(r"(?:HWaddr|Ethernet HW)\s+([0-9a-fA-F:]{10,})", output, re.IGNORECASE)
            if mac_candidates:
                res["mac"] = mac_candidates[0].strip()

        return res

    def _run_dcn_cmds(self):
        data = {"mac": "N/A", "sn": "N/A", "model": "N/A"}
        max_retries = 10

        for attempt in range(max_retries):
            if self._should_stop():
                return data

            self._drain_buffer()
            self.shell.send("get-system detail\n")

            out_buf, _ = self._read_until_remote([r"~#", r"@Yunke", r"China"], timeout=10)
            temp_data = self._parse_output(out_buf)

            sn_value = temp_data["sn"].strip()
            normalized_sn = sn_value.lower()
            mac_clean = temp_data["mac"].replace(":", "").replace("-", "").replace(".", "")

            sn_invalid = temp_data["sn"] == "N/A" or len(sn_value) < 8 or normalized_sn == "device-type"
            mac_invalid = temp_data["mac"] == "N/A" or len(mac_clean) != 12
            is_valid = not (sn_invalid or mac_invalid)

            if is_valid:
                data = temp_data
                break

            if attempt < max_retries - 1:
                detail = f"MAC:{temp_data['mac']}, SN:{temp_data['sn']}"
                self._log(f"[{self.ip}] 格式异常({detail})，第 {attempt + 1} 次重试...", "ping_fail")
                time.sleep(1.5)
            else:
                self._log(f"[{self.ip}] 多次获取仍格式错误，放弃。", "fail")
                data = temp_data

        return data

    def _run_repair_scripts(self):
        self._log(f"[{self.ip}] 正在修复 SSH...", "repair")
        cmds = [
            "cd /etc/ssh",
            "rm -rf /etc/ssh/* && cp -rf /rom/etc/ssh/* /etc/ssh/",
            "/etc/init.d/sshd stop",
            "/etc/init.d/sshd start",
        ]
        for cmd in cmds:
            if self._should_stop():
                break
            self._drain_buffer()
            self.shell.send(f"{cmd}\n")
            self._read_until_remote([r"~#", r"@Yunke", r"China"], timeout=5)
            time.sleep(0.5)

        self._log(f"[{self.ip}] 修复命令发送完毕，保持连接等待30秒...", "repair")
        wait_seconds = 30
        for i in range(wait_seconds, 0, -1):
            if self._should_stop():
                return
            time.sleep(1)
            if i % 10 == 0:
                self._log(f"[{self.ip}] 正在等待生效... 剩余 {i} 秒", "debug")

    def _strict_ping_check(self):
        if self.skip_ping:
            return True, "Skipped"
        if self.mode == "remote":
            if self._should_stop():
                return False, "Stopped"
            self._drain_buffer()
            self.shell.send(f"ping {self.ip} count 2\n")
            buf, _ = self._read_until_remote([r"[#>]"], timeout=8)

            if self._should_stop():
                return False, "Stopped"

            if "!!!!!" in buf:
                return True, "OK"
            if "Success rate is 100 percent" in buf:
                return True, "OK"
            if "Success rate is" in buf and "0 percent" not in buf:
                return True, "OK(丢包)"

            if "Success rate is 0 percent" in buf:
                return False, "0% (不通)"
            if "0 packets received" in buf:
                return False, "丢包"
            if "....." in buf and "!!!!!" not in buf:
                return False, "超时(.)"
            return False, "无响应"
        return True, "Local"

    def _attempt_ssh_remote(self):
        for pwd in DCN_PASSWORDS:
            if self._should_stop():
                return False, "Stopped"
            try:
                self.shell.send("\x03")
                time.sleep(0.2)
                self.shell.send("\n")
                self._read_until_remote([r"[#>]"], timeout=3)
                self._drain_buffer()

                self.shell.send(f"ssh {DCN_USER} {self.ip}\n")
                pats = [r"password:", r"\(yes/no\)\?", r"refused", r"timed out", r"unknown host", r"No route"]
                buf, idx = self._read_until_remote(pats, timeout=10)

                if idx >= 2:
                    return False, "Refused/NetErr"
                if idx == 1:
                    self.shell.send("yes\n")
                    buf, idx = self._read_until_remote([r"password:"], timeout=5)
                if idx == 0:
                    self.shell.send(f"{pwd}\n")
                    l_pats = [r"~#", r"@Yunke", r"China", r"GATEWAY", r"Permission denied", r"password:", r"closed", r"[#>]"]
                    l_buf, m_idx = self._read_until_remote(l_pats, timeout=15)

                    if m_idx in [0, 1, 2]:
                        return True, self._run_dcn_cmds()
                    if m_idx == 7:
                        if "GATEWAY" in l_buf:
                            continue
                        return True, self._run_dcn_cmds()
                    continue
            except Exception:
                continue
        return False, "Auth Failed (SSH)"

    def _attempt_telnet_remote(self):
        for pwd in DCN_PASSWORDS:
            if self._should_stop():
                return False, "Stopped"
            try:
                self.shell.send("\x03")
                time.sleep(0.2)
                self.shell.send("\n")
                self._read_until_remote([r"[#>]"], timeout=3)
                self._drain_buffer()

                self.shell.send(f"telnet {self.ip}\n")

                t_pats = [r"Login:", r"Username:", r"Password:", r"timed out", r"refused"]
                t_buf, t_idx = self._read_until_remote(t_pats, timeout=10)
                if t_idx >= 3:
                    return False, "Refused/Timeout"
                if t_idx == 0 or t_idx == 1:
                    self.shell.send(f"{DCN_USER}\n")
                    t_buf, t_idx = self._read_until_remote([r"Password:"], timeout=5)
                if t_idx == 2 or "Password" in t_buf or "password" in t_buf:
                    self.shell.send(f"{pwd}\n")
                    t_res, t_idx = self._read_until_remote([r"~#", r"@Yunke", r"GATEWAY", r"invalid", r"incorrect"], timeout=10)

                    if t_idx in [0, 1]:
                        data = self._run_dcn_cmds()
                        self._run_repair_scripts()
                        return True, data
            except Exception:
                continue
        return False, "Auth Failed (Telnet)"

    def run(self):
        res = {
            "ip": self.ip,
            "mac": "N/A",
            "sn": "N/A",
            "model": "N/A",
            "status": "failed",
            "error": "",
            "protocol": "",
        }
        try:
            if self._should_stop():
                res["error"] = "用户停止"
                return res

            if self.mode == "remote":
                time.sleep(random.uniform(0.5, 2.0))
                if not self._connect_jump_host():
                    res["error"] = "跳板机连接失败"
                    return res

                ok, msg = self._strict_ping_check()
                if not ok:
                    res["error"] = f"Ping {msg}"
                    return res

                s_ok, s_data = self._attempt_ssh_remote()
                if s_ok:
                    res.update(s_data)
                    res["status"] = "success"
                    res["protocol"] = "SSH"

                t_ok = False
                if not s_ok:
                    self._log(f"[{self.ip}] SSH失败 -> 试Telnet")
                    t_ok, t_data = self._attempt_telnet_remote()
                    if t_ok:
                        res.update(t_data)
                        res["status"] = "success"
                        res["protocol"] = "Telnet (AutoFixSSH)"

                if s_ok or t_ok:
                    missing = []
                    if res["mac"] == "N/A":
                        missing.append("MAC")
                    if res["sn"] == "N/A":
                        missing.append("SN")
                    if res["model"] == "N/A":
                        missing.append("Model")

                    if missing:
                        res["error"] = f"数据缺失({'/'.join(missing)})"
                        try:
                            with FILE_LOCK:
                                with open("debug_raw.txt", "a", encoding="utf-8") as f:
                                    f.write(
                                        f"\n\n{'='*10} DEBUG [{self.ip}] MISSING: {' '.join(missing)} {'='*10}\n"
                                    )
                                    f.write(self.raw_log)
                                    f.write("\n" + "=" * 40 + "\n")
                        except Exception:
                            pass
                else:
                    res["error"] = "SSH/Telnet密码均错误"
            else:
                pass
        except Exception as e:
            res["error"] = str(e)
        finally:
            if self.client:
                try:
                    self.client.close()
                except Exception:
                    pass
        return res


# --- UI (修改了 start/logic 流程) ---
class ScannerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DCYK AP信息采集工具 V40.0 (Global Clean & Retry)")
        self.root.geometry("850x700")
        self.msg_queue = queue.Queue()
        self.results = []
        self.failed_results = []
        self.is_running = False
        self.stop_event = threading.Event()
        self._setup_ui()
        self._check_queue()

    def _setup_ui(self):
        jh_f = ttk.LabelFrame(self.root, text="跳板机配置")
        jh_f.pack(fill="x", padx=10, pady=5)
        l1 = ttk.Frame(jh_f)
        l1.pack(fill="x", padx=5, pady=5)
        self.use_jh = tk.BooleanVar(value=False)
        ttk.Checkbutton(l1, text="使用跳板机", variable=self.use_jh, command=self.toggle_jh).pack(side="left")
        self.skip_ping = tk.BooleanVar(value=False)
        cb_skip = ttk.Checkbutton(l1, text="跳过 Ping (强制连接)", variable=self.skip_ping)
        cb_skip.pack(side="left", padx=20)
        self.jh_in = ttk.Frame(jh_f)
        self.jh_in.pack(fill="x", padx=20, pady=5)
        ttk.Label(self.jh_in, text="IP:").pack(side="left")
        self.e_jh_ip = ttk.Entry(self.jh_in, width=15)
        self.e_jh_ip.pack(side="left", padx=5)
        ttk.Label(self.jh_in, text="账号:").pack(side="left")
        self.e_jh_user = ttk.Entry(self.jh_in, width=12)
        self.e_jh_user.pack(side="left", padx=5)
        self.e_jh_user.insert(0, "admin")
        ttk.Label(self.jh_in, text="密码:").pack(side="left")
        self.e_jh_pass = ttk.Entry(self.jh_in, show="*", width=12)
        self.e_jh_pass.pack(side="left", padx=5)
        self.toggle_jh()

        tgt_f = ttk.LabelFrame(self.root, text="目标")
        tgt_f.pack(fill="x", padx=10, pady=5)
        ttk.Label(tgt_f, text="网段/IP:").pack(anchor="w", padx=5)
        self.txt_t = tk.Text(tgt_f, height=5)
        self.txt_t.pack(fill="x", padx=5)
        f_ex = ttk.Frame(tgt_f)
        f_ex.pack(fill="x", padx=5, pady=5)
        ttk.Label(f_ex, text="排除 (支持简写 1.1-30):").pack(side="left")
        self.e_ex = ttk.Entry(f_ex)
        self.e_ex.pack(side="left", fill="x", expand=True, padx=5)

        ctrl_f = ttk.Frame(self.root)
        ctrl_f.pack(fill="x", padx=10, pady=5)
        ttk.Label(ctrl_f, text="并发线程 (最多8):").pack(side="left")
        self.spin_th = ttk.Spinbox(ctrl_f, from_=1, to=8, width=5)
        self.spin_th.set(2)
        self.spin_th.pack(side="left", padx=5)

        btn_f = ttk.Frame(self.root)
        btn_f.pack(fill="x", padx=10, pady=5)
        self.b_run = ttk.Button(btn_f, text="▶ 开始", command=self.start)
        self.b_run.pack(side="left", padx=5)
        self.b_stop = ttk.Button(btn_f, text="⏹ 停止", command=self.stop, state="disabled")
        self.b_stop.pack(side="left", padx=5)
        ttk.Button(btn_f, text="💾 成功数据", command=self.export_success).pack(side="left", padx=15)
        self.b_fail = ttk.Button(btn_f, text="💾 失败记录", command=self.export_failures)
        self.b_fail.pack(side="left", padx=5)
        self.lbl_st = ttk.Label(btn_f, text="就绪")
        self.lbl_st.pack(side="right", padx=10)

        log_f = ttk.LabelFrame(self.root, text="日志")
        log_f.pack(fill="both", expand=True, padx=10, pady=5)
        self.log_t = scrolledtext.ScrolledText(log_f, state="disabled")
        self.log_t.pack(fill="both", expand=True, padx=5)
        self.log_t.tag_config("success", foreground="green")
        self.log_t.tag_config("fail", foreground="red")
        self.log_t.tag_config("ping_fail", foreground="orange")
        self.log_t.tag_config("debug", foreground="gray")
        self.log_t.tag_config("sys", foreground="blue")
        self.log_t.tag_config("repair", foreground="blue")

    def toggle_jh(self):
        state = "normal" if self.use_jh.get() else "disabled"
        for child in self.jh_in.winfo_children():
            if isinstance(child, ttk.Entry):
                child.configure(state=state)

    def log(self, msg, tag="info"):
        self.msg_queue.put(("log", msg, tag))

    def _check_queue(self):
        while not self.msg_queue.empty():
            msg_type, content, extra = self.msg_queue.get()
            if msg_type == "log":
                self.log_t.config(state="normal")
                self.log_t.insert(tk.END, content + "\n", extra)
                self.log_t.see(tk.END)
                self.log_t.config(state="disabled")
            elif msg_type == "status":
                self.lbl_st.config(text=content)
            elif msg_type == "finish":
                self.is_running = False
                self.b_run.config(state="normal")
                self.b_stop.config(state="disabled")
                messagebox.showinfo("完成", f"成功: {content['s']}, 失败: {content['f']}")
        self.root.after(100, self._check_queue)

    def start(self):
        if self.is_running:
            return
        t_str = self.txt_t.get("1.0", tk.END).strip()
        if not t_str:
            messagebox.showwarning("提示", "请输入目标网段")
            return

        use = self.use_jh.get()
        j_ip = self.e_jh_ip.get().strip()
        j_u = self.e_jh_user.get().strip()
        j_p = self.e_jh_pass.get().strip()

        if use and (not j_ip or not j_u or not j_p):
            messagebox.showerror("参数错误", "请填写跳板机信息")
            return

        try:
            mw = int(self.spin_th.get())
        except Exception:
            mw = 2
        if mw > 8:
            mw = 8

        self.is_running = True
        self.stop_event.clear()
        self.b_run.config(state="disabled")
        self.b_stop.config(state="normal")
        self.log_t.config(state="normal")
        self.log_t.delete("1.0", tk.END)
        self.log_t.config(state="disabled")
        self.results = []
        self.failed_results = []

        skip = self.skip_ping.get()
        j_c = {"ip": j_ip, "user": j_u, "pass": j_p} if use else None

        self.log(f"配置: 线程={mw}, 跳过Ping={skip}", "sys")
        threading.Thread(
            target=self.logic, args=(t_str, self.e_ex.get().strip(), use, j_c, mw, skip), daemon=True
        ).start()

    def stop(self):
        if self.is_running:
            if messagebox.askyesno("确认", "停止任务？"):
                self.stop_event.set()
                self.log("正在停止...", "sys")
                self.b_stop.config(state="disabled")

    def logic(self, t_str, e_str, use, j_c, mw, skip):
        if use and j_c:
            self.log("正在连接跳板机清理 SSH Key...", "sys")
            try:
                chk = paramiko.SSHClient()
                chk.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                chk.connect(j_c["ip"], username=j_c["user"], password=j_c["pass"], timeout=10)

                shell = chk.invoke_shell()
                shell.send("\n")
                time.sleep(0.5)
                while shell.recv_ready():
                    shell.recv(4096)

                shell.send("delete ssh-known-hosts\n")
                time.sleep(1.0)

                chk.close()
                self.log("跳板机环境清理完毕", "success")
            except Exception as e:
                self.log(f"跳板机预处理失败: {e}", "fail")
                self.msg_queue.put(("finish", {"s": 0, "f": 0}, None))
                return

        self.log("解析IP...", "debug")
        all_ips = parse_ip_input(t_str)
        ex_ips = parse_ip_input(e_str)
        targets = list(all_ips - ex_ips)
        self.log(f"目标数: {len(targets)}", "debug")

        if not targets:
            self.msg_queue.put(("finish", {"s": 0, "f": 0}, None))
            return

        mode = "remote" if use else "local"
        self.log("开始任务...", "sys")
        s, f = 0, 0

        with ThreadPoolExecutor(max_workers=mw) as exe:
            fut_map = {}
            for ip in targets:
                if self.stop_event.is_set():
                    break
                fut_map[
                    exe.submit(
                        DcnApCollector(
                            ip,
                            mode,
                            j_c,
                            skip,
                            lambda m, t="info": self.log(m, t),
                            self.stop_event,
                        ).run
                    )
                ] = ip

            for fut in as_completed(fut_map):
                r = fut.result()
                self.msg_queue.put(("status", f"{s + f}/{len(targets)}", None))
                if r["status"] == "success":
                    s += 1
                    self.log(f"[成功] {r['ip']} | {r['protocol']} | Model:{r['model']} | SN:{r['sn']}", "success")
                    self.results.append(r)
                else:
                    if r["error"] == "用户停止":
                        continue
                    f += 1
                    if "Ping" not in r["error"]:
                        tag = "fail"
                        err = r["error"].replace("\n", " ")
                        self.log(f"[失败] {r['ip']} -> {err}", tag)
                        self.failed_results.append(r)
                    else:
                        pass
        self.msg_queue.put(("finish", {"s": s, "f": f}, None))

    def export_success(self):
        if not self.results:
            messagebox.showinfo("提示", "无成功数据")
            return
        fp = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if fp:
            try:
                with open(fp, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["IP", "MAC", "SN", "Model", "Protocol"])
                    for item in self.results:
                        w.writerow([item["ip"], item["mac"], item["sn"], item.get("model", "N/A"), item.get("protocol", "")])
                messagebox.showinfo("成功", f"保存至 {fp}")
            except Exception as e:
                messagebox.showerror("错误", str(e))

    def export_failures(self):
        if not self.failed_results:
            messagebox.showinfo("提示", "无失败记录")
            return
        fp = filedialog.asksaveasfilename(defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if fp:
            try:
                with open(fp, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(["IP", "Error Reason"])
                    for item in self.failed_results:
                        w.writerow([item["ip"], item["error"]])
                messagebox.showinfo("成功", f"保存至 {fp}")
            except Exception as e:
                messagebox.showerror("错误", str(e))


if __name__ == "__main__":
    root = tk.Tk()
    app = ScannerApp(root)
    root.mainloop()
