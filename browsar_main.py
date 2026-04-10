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
import customtkinter as ctk
from tkinter import messagebox, ttk
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
    def get_hex_dump(file_path, max_bytes=8192, physical_mode=False):
        if not os.path.exists(file_path): return "[-] File Not Found or Access Denied."
        header = "Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |  ASCII\n"
        sep =    "--------  -----------------------------------------------  |  ----------------\n"
        output = [header, sep]
        try:
            with open(file_path, 'rb') as f:
                data = f.read(max_bytes)
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    offset = (0x4A2F3B000 + i) if physical_mode else i
                    hex_p = ' '.join(f"{b:02x}" for b in chunk)
                    asc_p = ''.join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                    output.append(f"{offset:08x}  {hex_p:<48}  |  {asc_p}\n")
            return "".join(output)
        except: return "[-] Read Error (File likely locked by OS)."

class BrowserScanner:
    @staticmethod
    def get_installed_browsers():
        user_p = os.environ['USERPROFILE']
        paths = {
            "Brave": os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data"),
            "Chrome": os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data"),
            "Edge": os.path.join(os.environ['LOCALAPPDATA'], r"Microsoft\Edge\User Data"),
            "Firefox": os.path.join(os.environ['APPDATA'], r"Mozilla\Firefox\Profiles"),
            "Tor": os.path.join(user_p, r"Desktop\Tor Browser\Browser\TorBrowser\Data\Browser")
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
            self.tree.column(col, width=250, anchor="w")
        
        for row in data: self.tree.insert("", "end", values=row)
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

# --- 4. MAIN DASHBOARD ---
class BrowsAR_App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Brows-AR | Professional Forensic Workstation")
        self.geometry("1400x900")
        ctk.set_appearance_mode("dark")
        
        self.current_browser_path = ""
        self.current_browser_name = ""

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
        
        self.welcome_text = ctk.CTkLabel(self.main_view, text="[*] SYSTEM TRIAGE COMPLETE\n\nSELECT SOURCE", font=("Consolas", 16))
        self.welcome_text.place(relx=0.5, rely=0.5, anchor="center")

    def load_browser_cockpit(self, name, path):
        self.current_browser_name, self.current_browser_path = name, path
        for widget in self.main_view.winfo_children(): widget.destroy()
        
        control_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        control_frame.pack(fill="x", padx=20, pady=15)
        ctk.CTkLabel(control_frame, text=f"TARGET: {name.upper()}", font=("Consolas", 18, "bold"), text_color="#1f538d").pack(side="left")
        
        self.analyze_btn = ctk.CTkButton(control_frame, text="⚡ RUN ANALYSIS", fg_color="#d35400", hover_color="#e67e22", 
                                        font=("Consolas", 12, "bold"), command=self.trigger_analysis)
        self.analyze_btn.pack(side="right", padx=10)

        self.tabview = ctk.CTkTabview(self.main_view, segmented_button_selected_color="#1f538d", command=self.on_tab_changed)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        for tab in ["Hex Explorer", "Passwords", "History", "Registry", "Prefetch"]: self.tabview.add(tab)

        self.hex_display = ctk.CTkTextbox(self.tabview.tab("Hex Explorer"), font=("Consolas", 14), wrap="none", fg_color="#000000")
        self.hex_display.pack(fill="both", expand=True, padx=10, pady=10)
        self.on_tab_changed()

    def on_tab_changed(self):
        """Intelligent Hex Observer: Syncs binary view with the active tab context."""
        active = self.tabview.get()
        self.hex_display.delete("0.0", "end")
        
        target_file = None
        if active == "Passwords":
            t = "logins.json" if self.current_browser_name in ["Tor", "Firefox"] else "Login Data"
            for r, d, f in os.walk(self.current_browser_path):
                if t in f: target_file = os.path.join(r, t); break
        elif active == "History":
            t = "places.sqlite" if self.current_browser_name in ["Tor", "Firefox"] else "History"
            for r, d, f in os.walk(self.current_browser_path):
                if t in f: target_file = os.path.join(r, t); break
        elif active == "Registry":
            target_file = r"C:\Windows\System32\config\SOFTWARE"
        elif active == "Prefetch":
            exe_map = {"Brave": "BRAVE.EXE", "Chrome": "CHROME.EXE", "Edge": "MSEDGE.EXE", "Firefox": "FIREFOX.EXE"}
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
        else:
            self.hex_display.insert("0.0", f"[-] No binary artifact found for {active}.")

    def trigger_analysis(self):
        tab = self.tabview.get()
        if tab == "Passwords": self.analyze_passwords()
        elif tab == "History": self.analyze_history()
        elif tab == "Registry": self.analyze_registry_deep()
        elif tab == "Prefetch": self.analyze_prefetch_deep()

    def analyze_passwords(self):
        try: win32security.RevertToSelf()
        except: pass
        ls_path = ""
        for r, d, f in os.walk(self.current_browser_path):
            if "Local State" in f: ls_path = os.path.join(r, "Local State"); break
        if not ls_path: return

        final_key = None
        try:
            with open(ls_path, "r", encoding="utf-8") as f: ls = json.load(f)
            if "app_bound_encrypted_key" in ls["os_crypt"]:
                raw_key = base64.b64decode(ls["os_crypt"]["app_bound_encrypted_key"])[4:]
                if impersonate_system():
                    try: stage1 = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
                    finally: win32security.RevertToSelf()
                final_key = win32crypt.CryptUnprotectData(stage1, None, None, None, 0)[1][-32:]
            elif "encrypted_key" in ls["os_crypt"]:
                raw_key = base64.b64decode(ls["os_crypt"]["encrypted_key"])[5:]
                final_key = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
        except: return

        db_path = ""
        for r, d, f in os.walk(self.current_browser_path):
            if "Login Data" in f: db_path = os.path.join(r, "Login Data"); break
        if not db_path: return

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
        AnalysisWindow(f"{self.current_browser_name} Credentials", ["URL", "User", "Password"], results)

    def analyze_history(self):
        target = "places.sqlite" if self.current_browser_name in ["Tor", "Firefox"] else "History"
        db_path = ""
        for r, d, f in os.walk(self.current_browser_path):
            if target in f: db_path = os.path.join(r, target); break
        if not db_path: return
        temp_db = "temp_hist.db"
        shutil.copyfile(db_path, temp_db)
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            query = "SELECT url, title, visit_count FROM moz_places WHERE visit_count > 0" if "sqlite" in target else "SELECT url, title, visit_count FROM urls"
            cursor.execute(query)
            data = cursor.fetchall()
            conn.close()
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
        AnalysisWindow(f"{self.current_browser_name} History", ["URL", "Page Title", "Visits"], data)

    def analyze_registry_deep(self):
        """Recursive Registry Triage matching the Brave script power."""
        reg_map = {
            "Brave": [r"SOFTWARE\BraveSoftware", r"SOFTWARE\WOW6432Node\BraveSoftware"],
            "Chrome": [r"SOFTWARE\Google\Chrome", r"SOFTWARE\WOW6432Node\Google\Chrome"],
            "Edge": [r"SOFTWARE\Microsoft\Edge", r"SOFTWARE\Microsoft\EdgeUpdate"]
        }
        paths = reg_map.get(self.current_browser_name, [])
        results = []

        def recursive_crawl(root, path):
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    n_sub, n_val, last_m = winreg.QueryInfoKey(key)
                    # Convert Registry Time
                    l_mod = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=last_m // 10)).strftime('%Y-%m-%d %H:%M:%S')
                    results.append((f"[KEY] {path}", f"Modified: {l_mod}"))
                    for i in range(n_val):
                        name, val, _ = winreg.EnumValue(key, i)
                        results.append((f"  -> {name}", str(val)))
                    for i in range(n_sub):
                        recursive_crawl(root, rf"{path}\{winreg.EnumKey(key, i)}")
            except: pass

        for p in paths: recursive_crawl(winreg.HKEY_LOCAL_MACHINE, p)
        AnalysisWindow(f"{self.current_browser_name} Registry Deep Scan", ["Artifact", "Value/Timestamp"], results)

    def analyze_prefetch_deep(self):
        """SCCA/MAM Header Parsing for detailed execution analytics."""
        exe_map = {"Brave": "BRAVE.EXE", "Chrome": "CHROME.EXE", "Edge": "MSEDGE.EXE", "Firefox": "FIREFOX.EXE"}
        exe_name = exe_map.get(self.current_browser_name, "")
        pf_dir = r"C:\Windows\Prefetch"
        evidence = []

        if os.path.exists(pf_dir):
            for f_name in os.listdir(pf_dir):
                if f_name.startswith(exe_name) and f_name.endswith(".pf"):
                    path = os.path.join(pf_dir, f_name)
                    stat = os.stat(path)
                    with open(path, "rb") as f:
                        header = f.read(8)
                        if header[0:3] == b'MAM':
                            run_info = f"Compressed (MAM) | Last: {datetime.datetime.fromtimestamp(stat.st_mtime)}"
                        else:
                            try:
                                f.seek(0xD0)
                                count = struct.unpack("<I", f.read(4))[0]
                                run_info = f"SCCA | Run Count: {count}"
                            except: run_info = "SCCA | Static Timestamp Only"
                    evidence.append((f_name, run_info))
        
        AnalysisWindow(f"{self.current_browser_name} Execution Evidence", ["Artifact", "Forensic Data"], evidence)

if __name__ == "__main__":
    if not is_admin(): ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else: app = BrowsAR_App(); app.mainloop()