import os
import sys
import ctypes
import sqlite3
import shutil
import json
import base64
import winreg
import datetime
import struct
import time
import subprocess
import requests
import websocket
import csv
import customtkinter as ctk
from tkinter import messagebox, ttk, filedialog
from Cryptodome.Cipher import AES
import win32crypt
import win32security
import win32api
import win32con
import psutil

# --- 1. SYSTEM PRIVILEGE LOGIC ---
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def impersonate_system():
    try:
        h_token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 
                                               win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
        priv_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
        win32security.AdjustTokenPrivileges(h_token, 0, [(priv_id, win32security.SE_PRIVILEGE_ENABLED)])
        target_pid = next(p.info['pid'] for p in psutil.process_iter(['name', 'pid']) if p.info['name'].lower() == 'winlogon.exe')
        h_proc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, target_pid)
        h_tok = win32security.OpenProcessToken(h_proc, win32security.TOKEN_DUPLICATE | win32security.TOKEN_QUERY)
        new_tok = win32security.DuplicateTokenEx(h_tok, win32security.SecurityImpersonation, 
                                               win32security.TOKEN_ALL_ACCESS, win32security.TokenPrimary)
        win32security.ImpersonateLoggedOnUser(new_tok)
        return True
    except: return False

# --- 2. FORENSIC ENGINES ---
class HexEngine:
    @staticmethod
    def get_hex_dump(file_path, max_bytes=8192):
        if not os.path.exists(file_path): return "[-] File Not Found or Access Denied."
        header = "Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |  ASCII\n"
        sep =    "--------  -----------------------------------------------  |  ----------------\n"
        output = [header, sep]
        try:
            with open(file_path, 'rb') as f:
                data = f.read(max_bytes)
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    hex_p = ' '.join(f"{b:02x}" for b in chunk)
                    asc_p = ''.join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                    output.append(f"{i:08x}  {hex_p:<48}  |  {asc_p}\n")
            return "".join(output)
        except: return "[-] Read Error (File locked)."

class BrowserScanner:
    @staticmethod
    def get_installed_browsers():
        paths = {
            "Brave": os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data"),
            "Chrome": os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data"),
            "Edge": os.path.join(os.environ['LOCALAPPDATA'], r"Microsoft\Edge\User Data")
        }
        detected = []
        for n, p in paths.items():
            if os.path.exists(p): detected.append((n, p))
        return detected

# --- 3. ANALYSIS POPUP WINDOW ---
class AnalysisWindow(ctk.CTkToplevel):
    def __init__(self, title, columns, data):
        super().__init__()
        self.title(title)
        self.geometry("1100x600")
        self.attributes('-topmost', True)
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1a1a1a", foreground="white", fieldbackground="#1a1a1a", borderwidth=0)
        style.configure("Treeview.Heading", background="#333333", foreground="white", relief="flat")
        
        self.tree = ttk.Treeview(self, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=300, anchor="w")
        
        for row in data: self.tree.insert("", "end", values=row)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

# --- 4. MAIN DASHBOARD ---
class BrowsAR_App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Brows-AR | Ultimate Forensic Suite")
        self.geometry("1400x900")
        ctk.set_appearance_mode("dark")
        
        self.current_browser_path = ""
        self.current_browser_name = ""
        self.last_results = []
        self.last_headers = []

        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.logo_label = ctk.CTkLabel(self.sidebar, text="Brows-AR", font=("Consolas", 28, "bold"))
        self.logo_label.pack(padx=20, pady=40)

        for name, path in BrowserScanner.get_installed_browsers():
            btn = ctk.CTkButton(self.sidebar, text=f"Investigate {name}", font=("Consolas", 13),
                                command=lambda n=name, p=path: self.load_browser_cockpit(n, p))
            btn.pack(pady=10, padx=20)

        self.main_view = ctk.CTkFrame(self, corner_radius=15, fg_color="#121212")
        self.main_view.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        
        self.welcome_text = ctk.CTkLabel(self.main_view, text="[*] SYSTEM TRIAGE COMPLETE\n\nSELECT A TARGET", font=("Consolas", 16))
        self.welcome_text.place(relx=0.5, rely=0.5, anchor="center")

    def load_browser_cockpit(self, name, path):
        self.current_browser_name, self.current_browser_path = name, path
        for widget in self.main_view.winfo_children(): widget.destroy()
        
        control_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        control_frame.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(control_frame, text=f"TARGET: {name.upper()}", font=("Consolas", 18, "bold"), text_color="#1f538d").pack(side="left")
        
        self.export_btn = ctk.CTkButton(control_frame, text="📥 EXPORT REPORT", fg_color="#27ae60", hover_color="#2ecc71", 
                                        font=("Consolas", 12, "bold"), command=self.export_evidence)
        self.export_btn.pack(side="right", padx=10)

        self.analyze_btn = ctk.CTkButton(control_frame, text="⚡ RUN ANALYSIS", fg_color="#d35400", hover_color="#e67e22", 
                                        font=("Consolas", 12, "bold"), command=self.trigger_analysis)
        self.analyze_btn.pack(side="right", padx=10)

        self.tabview = ctk.CTkTabview(self.main_view, segmented_button_selected_color="#1f538d", command=self.on_tab_changed)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Tabs for all browsers
        tabs = ["Hex Explorer", "Passwords", "History", "Registry", "Prefetch"]
        if name == "Brave": tabs.append("Cookies")
        
        for t in tabs: self.tabview.add(t)

        self.hex_display = ctk.CTkTextbox(self.tabview.tab("Hex Explorer"), font=("Consolas", 14), wrap="none", fg_color="#000000")
        self.hex_display.pack(fill="both", expand=True, padx=10, pady=10)
        self.on_tab_changed()

    def on_tab_changed(self):
        active = self.tabview.get()
        self.hex_display.delete("0.0", "end")
        
        target_file = None
        if active == "Passwords":
            t = "Login Data"
            for r, d, f in os.walk(self.current_browser_path):
                if t in f: target_file = os.path.join(r, t); break
        elif active == "History":
            t = "History"
            for r, d, f in os.walk(self.current_browser_path):
                if t in f: target_file = os.path.join(r, t); break
        elif active == "Registry":
            target_file = r"C:\Windows\System32\config\SOFTWARE"
        elif active == "Prefetch":
            exe_map = {"Brave": "BRAVE.EXE", "Chrome": "CHROME.EXE", "Edge": "MSEDGE.EXE"}
            prefix = exe_map.get(self.current_browser_name, "")
            pf_dir = r"C:\Windows\Prefetch"
            if os.path.exists(pf_dir):
                pfs = [os.path.join(pf_dir, f) for f in os.listdir(pf_dir) if f.startswith(prefix)]
                if pfs: target_file = max(pfs, key=os.path.getmtime)
        else:
            t = "Local State"
            for r, d, f in os.walk(self.current_browser_path):
                if t in f: target_file = os.path.join(r, t); break

        if target_file and os.path.exists(target_file):
            self.hex_display.insert("end", f"[*] HEX OBSERVER: MAPPING {active.upper()} CONTEXT\n")
            self.hex_display.insert("end", f"[*] SOURCE: {target_file}\n" + "="*80 + "\n")
            self.hex_display.insert("end", HexEngine.get_hex_dump(target_file))

    def trigger_analysis(self):
        tab = self.tabview.get()
        if tab == "Passwords": self.analyze_passwords()
        elif tab == "History": self.analyze_history()
        elif tab == "Registry": self.analyze_registry_deep()
        elif tab == "Prefetch": self.analyze_prefetch_deep()
        elif tab == "Cookies" and self.current_browser_name == "Brave": self.analyze_brave_cookies()

    # --- BRAVE COOKIE BYPASS ---
    def analyze_brave_cookies(self):
        messagebox.showinfo("Brows-AR", "Starting Headless Bypass. Brave will close temporarily.")
        brave_exe = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
        subprocess.run("taskkill /F /IM brave.exe /T", shell=True, capture_output=True)
        time.sleep(2)

        cmd = f'"{brave_exe}" --remote-debugging-port=9222 --user-data-dir="{self.current_browser_path}" --remote-allow-origins=* --headless --disable-gpu'
        subprocess.Popen(cmd, shell=True)
        time.sleep(5)

        try:
            resp = requests.get("http://localhost:9222/json")
            ws_url = resp.json()[0]['webSocketDebuggerUrl']
            ws = websocket.create_connection(ws_url)
            ws.send(json.dumps({"id": 1, "method": "Network.getAllCookies"}))
            result = json.loads(ws.recv())
            cookies = result.get('result', {}).get('cookies', [])
            ws.close()
            subprocess.run("taskkill /F /IM brave.exe /T", shell=True, capture_output=True)
            
            data = [(c['domain'], c['name'], c['value'][:50]+"...") for c in cookies]
            self.last_results, self.last_headers = data, ["Domain", "Name", "Value"]
            AnalysisWindow("Brave v20 Cookies", self.last_headers, data)
        except Exception as e:
            messagebox.showerror("Bypass Error", f"Failed: {e}")

    # --- SHARED ANALYSIS LOGIC ---
    def analyze_passwords(self):
        try: win32security.RevertToSelf()
        except: pass
        ls_path = ""
        for r, d, f in os.walk(self.current_browser_path):
            if "Local State" in f: ls_path = os.path.join(r, "Local State"); break
        if not ls_path: return

        try:
            with open(ls_path, "r", encoding="utf-8") as f: ls = json.load(f)
            if "app_bound_encrypted_key" in ls["os_crypt"]:
                raw_key = base64.b64decode(ls["os_crypt"]["app_bound_encrypted_key"])[4:]
                if impersonate_system():
                    try: stage1 = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
                    finally: win32security.RevertToSelf()
                final_key = win32crypt.CryptUnprotectData(stage1, None, None, None, 0)[1][-32:]
            else:
                raw_key = base64.b64decode(ls["os_crypt"]["encrypted_key"])[5:]
                final_key = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
        except: return

        db_path = ""
        for r, d, f in os.walk(self.current_browser_path):
            if "Login Data" in f: db_path = os.path.join(r, "Login Data"); break
        
        temp_db = "temp_pass.db"
        shutil.copyfile(db_path, temp_db)
        results = []
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, username_element, password_value FROM logins")
            for url, u_val, u_el, enc_p in cursor.fetchall():
                user = u_val if u_val.strip() else (u_el if u_el.strip() else "[No User]")
                try:
                    iv, pay = enc_p[3:15], enc_p[15:]
                    cipher = AES.new(final_key, AES.MODE_GCM, iv)
                    if self.current_browser_name in ["Chrome", "Edge", "Brave"]: cipher.update(b'browser')
                    dec_p = cipher.decrypt(pay[:-16]).decode('utf-8', errors='ignore')
                    results.append((url, user, dec_p))
                except: results.append((url, user, "[Failed]"))
            conn.close()
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
        self.last_results, self.last_headers = results, ["URL", "User", "Password"]
        AnalysisWindow(f"{self.current_browser_name} Credentials", self.last_headers, results)

    def analyze_history(self):
        db_path = ""
        for r, d, f in os.walk(self.current_browser_path):
            if "History" in f: db_path = os.path.join(r, "History"); break
        if not db_path: return
        temp_db = "temp_hist.db"
        shutil.copyfile(db_path, temp_db)
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count FROM urls")
            data = cursor.fetchall()
            conn.close()
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
        self.last_results, self.last_headers = data, ["URL", "Page Title", "Visits"]
        AnalysisWindow(f"{self.current_browser_name} History", self.last_headers, data)

    def analyze_registry_deep(self):
        reg_map = {
            "Brave": [r"SOFTWARE\BraveSoftware", r"SOFTWARE\WOW6432Node\BraveSoftware\Update\ClientState\{AFE543B7-A336-4495-BA22-7F37F2A25387}"],
            "Chrome": [r"SOFTWARE\Google\Chrome", r"SOFTWARE\WOW6432Node\Google\Update\ClientState\{8A69D345-D564-463c-AFF1-A69D9E530F96}"],
            "Edge": [r"SOFTWARE\Microsoft\Edge", r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-8008-4CBD-B6D2-8C97FE7E9062}"]
        }
        paths, results = reg_map.get(self.current_browser_name, []), []
        def recursive_crawl(root, path):
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    n_sub, n_val, last_m = winreg.QueryInfoKey(key)
                    l_mod = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=last_m // 10)).strftime('%Y-%m-%d %H:%M:%S')
                    results.append((f"[KEY] {path}", f"Modified: {l_mod}"))
                    for i in range(n_val):
                        try:
                            name, val, _ = winreg.EnumValue(key, i)
                            results.append((f"  -> {name}", str(val)))
                        except: pass
                    for i in range(n_sub):
                        try: recursive_crawl(root, rf"{path}\{winreg.EnumKey(key, i)}")
                        except: pass
            except: pass
        for p in paths: recursive_crawl(winreg.HKEY_LOCAL_MACHINE, p)
        self.last_results, self.last_headers = results, ["Artifact", "Value/Timestamp"]
        AnalysisWindow(f"{self.current_browser_name} Registry Deep Scan", self.last_headers, results)

    def analyze_prefetch_deep(self):
        exe_map = {"Brave": "BRAVE.EXE", "Chrome": "CHROME.EXE", "Edge": "MSEDGE.EXE"}
        exe_name, pf_dir, evidence = exe_map.get(self.current_browser_name, ""), r"C:\Windows\Prefetch", []
        if os.path.exists(pf_dir):
            for f_name in os.listdir(pf_dir):
                if f_name.upper().startswith(exe_name) and f_name.endswith(".pf"):
                    path = os.path.join(pf_dir, f_name)
                    stat = os.stat(path)
                    with open(path, "rb") as f:
                        header = f.read(8)
                        if header[0:3] == b'MAM': run_info = f"Compressed (MAM) | Last: {datetime.datetime.fromtimestamp(stat.st_mtime)}"
                        else:
                            try:
                                f.seek(0xD0); count = struct.unpack("<I", f.read(4))[0]
                                run_info = f"SCCA | Run Count: {count}"
                            except: run_info = f"SCCA | Last Run: {datetime.datetime.fromtimestamp(stat.st_mtime)}"
                    evidence.append((f_name, run_info))
        self.last_results, self.last_headers = evidence, ["Artifact", "Forensic Data"]
        AnalysisWindow(f"{self.current_browser_name} Execution Evidence", self.last_headers, evidence)

    # --- REPORT EXPORTER ---
    def export_evidence(self):
        if not self.last_results:
            messagebox.showwarning("Brows-AR", "No analysis data to export. Run analysis on a tab first!")
            return
        f_path = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML Report", "*.html"), ("CSV Report", "*.csv")])
        if not f_path: return
        try:
            if f_path.endswith(".csv"):
                with open(f_path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f); w.writerow(self.last_headers); w.writerows(self.last_results)
            elif f_path.endswith(".html"):
                html = f"<html><body style='font-family:monospace; background:#121212; color:white;'><h1>Brows-AR Report: {self.current_browser_name}</h1><table border='1' style='width:100%; border-collapse:collapse;'>"
                html += "<tr>" + "".join([f"<th style='background:#333; padding:10px;'>{h}</th>" for h in self.last_headers]) + "</tr>"
                for row in self.last_results:
                    html += "<tr>" + "".join([f"<td style='padding:8px; border:1px solid #444;'>{val}</td>" for val in row]) + "</tr>"
                html += "</table></body></html>"
                with open(f_path, "w", encoding="utf-8") as f: f.write(html)
            messagebox.showinfo("Brows-AR", f"Forensic Report Saved: {f_path}")
        except Exception as e: messagebox.showerror("Export Failed", f"Error: {e}")

if __name__ == "__main__":
    if not is_admin(): ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else: app = BrowsAR_App(); app.mainloop()