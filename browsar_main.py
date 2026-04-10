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

# --- 2. FORENSIC HEX ENGINE ---
class HexEngine:
    @staticmethod
    def get_hex_dump(file_path, offset=0, page_size=4096):
        if not file_path or not os.path.exists(file_path): return "[-] Artifact File Not Found."
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset); data = f.read(page_size)
                header = f"[*] SOURCE: {os.path.basename(file_path)} | OFFSET: {offset}\n"
                header += "Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |  ASCII\n"
                sep =    "--------  -----------------------------------------------  |  ----------------\n"
                output = [header, sep]
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    hex_p = ' '.join(f"{b:02x}" for b in chunk)
                    asc_p = ''.join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                    output.append(f"{(offset+i):08x}  {hex_p:<48}  |  {asc_p}\n")
            return "".join(output)
        except: return "[-] Read Error: Access Denied by System."

# --- 3. ANALYSIS POPUP WINDOW ---
class AnalysisWindow(ctk.CTkToplevel):
    def __init__(self, title, columns, data):
        super().__init__()
        self.title(title)
        self.geometry("1200x700")
        self.attributes('-topmost', True)
        
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#1a1a1a", foreground="white", fieldbackground="#1a1a1a", borderwidth=0)
        style.configure("Treeview.Heading", background="#333333", foreground="white", relief="flat")
        
        self.tree = ttk.Treeview(self, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=400, anchor="w")
        
        for row in data: self.tree.insert("", "end", values=row)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

# --- 4. MAIN DASHBOARD ---
class BrowsAR_App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Brows-AR | Ultimate Forensic Suite")
        self.geometry("1450x900")
        ctk.set_appearance_mode("dark")
        
        self.current_browser_path = ""
        self.current_browser_name = ""
        self.tab_offsets = {}
        self.page_size = 4096 
        self.displays = {}
        self.last_results = []
        self.last_headers = []

        # Sidebar
        self.sidebar = ctk.CTkFrame(self, width=240, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        ctk.CTkLabel(self.sidebar, text="Brows-AR", font=("Consolas", 28, "bold")).pack(padx=20, pady=40)

        self.browser_paths = {
            "Brave": os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data"),
            "Chrome": os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data"),
            "Edge": os.path.join(os.environ['LOCALAPPDATA'], r"Microsoft\Edge\User Data")
        }

        for name in self.browser_paths:
            if os.path.exists(self.browser_paths[name]):
                btn = ctk.CTkButton(self.sidebar, text=f"Investigate {name}", font=("Consolas", 13),
                                    command=lambda n=name, p=self.browser_paths[name]: self.load_browser_cockpit(n, p))
                btn.pack(pady=10, padx=20)

        self.main_view = ctk.CTkFrame(self, corner_radius=15, fg_color="#121212")
        self.main_view.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(self.main_view, text="[*] SYSTEM TRIAGE READY", font=("Consolas", 16)).place(relx=0.5, rely=0.5, anchor="center")

    def load_browser_cockpit(self, name, path):
        self.current_browser_name, self.current_browser_path = name, path
        for widget in self.main_view.winfo_children(): widget.destroy()
        
        control_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        control_frame.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(control_frame, text=f"TARGET: {name.upper()}", font=("Consolas", 18, "bold"), text_color="#1f538d").pack(side="left")
        
        ctk.CTkButton(control_frame, text="📥 EXPORT", fg_color="#27ae60", command=self.export_evidence).pack(side="right", padx=10)
        ctk.CTkButton(control_frame, text="⚡ RUN ANALYSIS", fg_color="#d35400", command=self.trigger_analysis).pack(side="right", padx=10)

        self.tabview = ctk.CTkTabview(self.main_view, command=self.on_tab_changed)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        tabs = ["Hex Explorer", "Passwords", "History", "Registry", "Prefetch"]
        if name == "Brave": tabs.append("Cookies")
        
        for t in tabs: 
            self.tabview.add(t)
            self.tab_offsets[t] = 0
            if t == "Registry": self.setup_registry_explorer(t)
            else: self.setup_hex_tab(t)

    def setup_hex_tab(self, t):
        container = ctk.CTkFrame(self.tabview.tab(t), fg_color="transparent")
        container.pack(fill="both", expand=True)
        txt = ctk.CTkTextbox(container, font=("Consolas", 14), wrap="none", fg_color="#000000", text_color="#ffffff")
        txt.pack(fill="both", expand=True, padx=10, pady=(10, 5))
        self.displays[t] = txt
        nav = ctk.CTkFrame(container, fg_color="transparent", height=40)
        nav.pack(fill="x", side="bottom", padx=10, pady=5)
        ctk.CTkButton(nav, text=" < Prev Page ", width=100, command=lambda tab=t: self.change_page(tab, -1)).pack(side="left")
        ctk.CTkButton(nav, text=" Next Page > ", width=100, command=lambda tab=t: self.change_page(tab, 1)).pack(side="right")

    def setup_registry_explorer(self, t):
        container = ctk.CTkFrame(self.tabview.tab(t), fg_color="#1a1a1a")
        container.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Splitter logic for tree vs values
        self.reg_tree = ttk.Treeview(container, show="tree")
        self.reg_tree.pack(side="left", fill="both", expand=True)
        self.reg_tree.bind("<<TreeviewSelect>>", self.on_registry_key_selected)
        
        self.reg_values = ttk.Treeview(container, columns=("Name", "Data"), show="headings")
        self.reg_values.heading("Name", text="PROPERTY"); self.reg_values.heading("Data", text="VALUE")
        self.reg_values.column("Name", width=200); self.reg_values.column("Data", width=400)
        self.reg_values.pack(side="right", fill="both", expand=True)
        self.refresh_registry_tree()

    def get_reg_targets(self):
        """Unified hit list for all browsers based on your forensic script."""
        if self.current_browser_name == "Brave":
            return [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\BraveSoftware"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\BraveSoftware"),
                (winreg.HKEY_CURRENT_USER, r"Software\BraveSoftware"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Brave-Browser"),
                (winreg.HKEY_CLASSES_ROOT, r"BraveHTML")
            ]
        elif self.current_browser_name == "Chrome":
            return [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Google\Chrome"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Google\Update\ClientState\{8A69D345-D564-463c-AFF1-A69D9E530F96}"),
                (winreg.HKEY_CURRENT_USER, r"Software\Google\Chrome")
            ]
        else: # Edge
            return [
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Edge"),
                (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-8008-4CBD-B6D2-8C97FE7E9062}"),
                (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Edge")
            ]

    def refresh_registry_tree(self):
        for i in self.reg_tree.get_children(): self.reg_tree.delete(i)
        targets = self.get_reg_targets()
        
        for root, path in targets:
            root_name = "HKLM" if root == winreg.HKEY_LOCAL_MACHINE else ("HKCU" if root == winreg.HKEY_CURRENT_USER else "HKCR")
            node = self.reg_tree.insert("", "end", text=f"{root_name}: {path}", values=(root, path))
            self.add_reg_subkeys(node, root, path)

    def add_reg_subkeys(self, parent_node, root, path):
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                num_subkeys, _, _ = winreg.QueryInfoKey(key)
                for i in range(num_subkeys):
                    name = winreg.EnumKey(key, i)
                    new_path = rf"{path}\{name}"
                    node = self.reg_tree.insert(parent_node, "end", text=name, values=(root, new_path))
                    # Note: Deep recursion can be slow in UI, so we only go 1 level deep or use on-demand
        except: pass

    def on_registry_key_selected(self, event):
        selected = self.reg_tree.selection()[0]
        root, path = self.reg_tree.item(selected, "values")
        root = int(root) # Ensure root is the handle
        
        for i in self.reg_values.get_children(): self.reg_values.delete(i)
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                _, num_values, _ = winreg.QueryInfoKey(key)
                for i in range(num_values):
                    name, data, _ = winreg.EnumValue(key, i)
                    self.reg_values.insert("", "end", values=(name, str(data)))
        except: pass

    def trigger_analysis(self):
        tab = self.tabview.get()
        if tab == "Passwords": self.analyze_passwords()
        elif tab == "History": self.analyze_history()
        elif tab == "Registry": self.analyze_registry_deep()
        elif tab == "Prefetch": self.analyze_prefetch_deep()
        elif tab == "Cookies": self.analyze_brave_cookies()

    def analyze_registry_deep(self):
        """Matches your standalone forensic script's depth and multi-hive logic."""
        targets = self.get_reg_targets()
        results = []

        def crawl(root, path):
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    n_s, n_v, l_m = winreg.QueryInfoKey(key)
                    t_m = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=l_m // 10)).strftime('%Y-%m-%d %H:%M:%S')
                    results.append((f"[KEY] {path}", f"Last Modified: {t_m}"))
                    for i in range(n_v):
                        n, v, _ = winreg.EnumValue(key, i)
                        results.append((f"  -> {n}", str(v)))
                    for i in range(n_s):
                        crawl(root, rf"{path}\{winreg.EnumKey(key, i)}")
            except: pass

        for root, path in targets: crawl(root, path)
        self.last_results, self.last_headers = results, ["Artifact Path", "Value / Metadata"]
        AnalysisWindow(f"{self.current_browser_name} Comprehensive Registry Scan", self.last_headers, results)

    # --- OTHER FORENSIC METHODS (Unified with existing code) ---
    def analyze_passwords(self):
        try: win32security.RevertToSelf()
        except: pass
        ls_path = self.get_artifact_path("Hex Explorer")
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
            
            db_path = self.get_artifact_path("Passwords")
            temp_db = "temp_pass.db"; shutil.copyfile(db_path, temp_db)
            res = []
            conn = sqlite3.connect(temp_db); cur = conn.cursor()
            cur.execute("SELECT origin_url, username_value, username_element, password_value FROM logins")
            for url, u_v, u_e, enc_p in cur.fetchall():
                user = u_v if u_v.strip() else (u_e if u_e.strip() else "[No User]")
                try:
                    iv, pay = enc_p[3:15], enc_p[15:]; cip = AES.new(final_key, AES.MODE_GCM, iv)
                    if self.current_browser_name in ["Chrome", "Edge", "Brave"]: cip.update(b'browser')
                    dec_p = cip.decrypt(pay[:-16]).decode('utf-8', errors='ignore')
                    res.append((url, user, dec_p))
                except: res.append((url, user, "[Encrypted]"))
            conn.close(); os.remove(temp_db)
            self.last_results, self.last_headers = res, ["URL", "User", "Password"]
            AnalysisWindow(f"{self.current_browser_name} Credentials", self.last_headers, res)
        except: pass

    def analyze_history(self):
        path = self.get_artifact_path("History")
        temp = "temp_hist.db"; shutil.copyfile(path, temp)
        try:
            conn = sqlite3.connect(temp); cur = conn.cursor()
            cur.execute("SELECT url, title, visit_count FROM urls")
            data = cur.fetchall(); conn.close(); os.remove(temp)
            self.last_results, self.last_headers = data, ["URL", "Title", "Visits"]
            AnalysisWindow(f"{self.current_browser_name} History", self.last_headers, data)
        except: pass

    def analyze_prefetch_deep(self):
        exe_map = {"Brave": "BRAVE.EXE", "Chrome": "CHROME.EXE", "Edge": "MSEDGE.EXE"}
        exe, pf_dir, res = exe_map.get(self.current_browser_name, ""), r"C:\Windows\Prefetch", []
        for f in os.listdir(pf_dir):
            if f.upper().startswith(exe) and f.endswith(".pf"):
                path = os.path.join(pf_dir, f); stat = os.stat(path)
                with open(path, "rb") as fd:
                    h = fd.read(8); info = f"MAM Compressed | {datetime.datetime.fromtimestamp(stat.st_mtime)}" if h[0:3] == b'MAM' else f"SCCA Standard | Offset 0xD0 Check"
                res.append((f, info))
        self.last_results, self.last_headers = res, ["Artifact", "Execution Data"]
        AnalysisWindow(f"{self.current_browser_name} Prefetch", self.last_headers, res)

    def analyze_brave_cookies(self):
        brave_exe = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
        subprocess.run("taskkill /F /IM brave.exe /T", shell=True, capture_output=True)
        time.sleep(2); cmd = f'"{brave_exe}" --remote-debugging-port=9222 --user-data-dir="{self.current_browser_path}" --headless --disable-gpu'
        subprocess.Popen(cmd, shell=True); time.sleep(5)
        try:
            resp = requests.get("http://localhost:9222/json")
            ws = websocket.create_connection(resp.json()[0]['webSocketDebuggerUrl'])
            ws.send(json.dumps({"id": 1, "method": "Network.getAllCookies"}))
            cookies = json.loads(ws.recv()).get('result', {}).get('cookies', [])
            ws.close(); subprocess.run("taskkill /F /IM brave.exe /T", shell=True, capture_output=True)
            res = [(c['domain'], c['name'], c['value'][:30]+"...") for c in cookies]
            self.last_results, self.last_headers = res, ["Domain", "Name", "Value"]
            AnalysisWindow("Brave Cookies", self.last_headers, res)
        except: pass

    def on_tab_changed(self):
        active = self.tabview.get()
        if active == "Registry" or active not in self.displays: return
        txt = self.displays[active]; txt.delete("0.0", "end")
        path = self.get_artifact_path(active)
        if path: txt.insert("end", HexEngine.get_hex_dump(path, offset=self.tab_offsets.get(active, 0)))

    def change_page(self, tab, direction):
        self.tab_offsets[tab] = max(0, self.tab_offsets.get(tab, 0) + (direction * self.page_size))
        self.on_tab_changed()

    def get_artifact_path(self, active):
        t = {"Passwords": "Login Data", "History": "History", "Cookies": "Cookies"}.get(active, "Local State")
        for r, d, f in os.walk(self.current_browser_path):
            if t in f: return os.path.join(r, t)
        return None

    def export_evidence(self):
        if not self.last_results: return
        f = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML Report", "*.html"), ("CSV", "*.csv")])
        if not f: return
        try:
            if f.endswith(".csv"):
                with open(f, "w", newline="", encoding="utf-8") as fd:
                    w = csv.writer(fd); w.writerow(self.last_headers); w.writerows(self.last_results)
            elif f.endswith(".html"):
                html = f"<html><body style='font-family:monospace; background:#121212; color:white;'><h1>Report: {self.current_browser_name}</h1><table border='1'>"
                html += "<tr>" + "".join([f"<th>{h}</th>" for h in self.last_headers]) + "</tr>"
                for row in self.last_results: html += "<tr>" + "".join([f"<td>{v}</td>" for v in row]) + "</tr>"
                html += "</table></body></html>"
                with open(f, "w", encoding="utf-8") as fd: fd.write(html)
            messagebox.showinfo("Brows-AR", f"Saved: {f}")
        except: pass

if __name__ == "__main__":
    if not is_admin(): ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else: app = BrowsAR_App(); app.mainloop()