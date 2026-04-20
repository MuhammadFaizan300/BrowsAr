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
import tkinter as _tk
import threading as _threading
try:
    import pystray as _pystray
    from PIL import Image as _PilImage, ImageDraw as _PilDraw, ImageFont as _PilFont, ImageTk as _PilImageTk
    _HAS_TRAY = True
except ImportError:
    _HAS_TRAY = False
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

def find_tor_browser():
    """Locate the Tor Browser installation root directory."""
    home = os.path.expanduser("~")
    candidates = [
        os.path.join(home, "Desktop",   "Tor Browser"),
        os.path.join(home, "Downloads", "Tor Browser"),
        os.path.join(home, "Documents", "Tor Browser"),
        os.path.join(home, "AppData", "Local", "Tor Browser"),
        r"C:\Program Files\Tor Browser",
        r"C:\Program Files (x86)\Tor Browser",
    ]
    for d in candidates:
        if os.path.exists(os.path.join(d, "Browser", "firefox.exe")):
            return d
    # NSIS installer registry entry
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Tor Browser") as k:
            loc = winreg.QueryValueEx(k, "InstallLocation")[0]
            if os.path.exists(loc):
                return loc
    except OSError:
        pass
    # MuiCache fallback
    try:
        mui = (r"Software\Classes\Local Settings\Software\Microsoft"
               r"\Windows\Shell\MuiCache")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mui) as k:
            for i in range(winreg.QueryInfoKey(k)[1]):
                n, _, _ = winreg.EnumValue(k, i)
                nl = n.lower()
                if "tor browser" in nl and "firefox.exe" in nl:
                    marker = "\\browser\\firefox.exe"
                    idx = nl.find(marker)
                    if idx != -1:
                        root = n[:idx]
                        if os.path.exists(root):
                            return root
    except OSError:
        pass
    return None

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

# colour tokens ─ one place to change the whole palette
_C_DARK = {
    "bg":         "#0d0d0d",  "surface":    "#141414",  "surface2":   "#1c1c1c",
    "border":     "#2a2a2a",  "accent":     "#4f8ef7",  "accent_dim": "#1e3a6e",
    "danger":     "#e05252",  "success":    "#3dba7a",  "warning":    "#e0a030",
    "text":       "#e8e8e8",  "text_dim":   "#888888",  "text_faint": "#444444",
    "mono":       "Consolas", "sans":       "Segoe UI",
}
_C_LIGHT = {
    "bg":         "#f0f2f5",  "surface":    "#ffffff",  "surface2":   "#f5f7fa",
    "border":     "#dde1e7",  "accent":     "#4272d4",  "accent_dim": "#cfe0ff",
    "danger":     "#c53030",  "success":    "#1e7e3e",  "warning":    "#a06000",
    "text":       "#1a1a2e",  "text_dim":   "#4a5568",  "text_faint": "#a0aec0",
    "mono":       "Consolas", "sans":       "Segoe UI",
}
# _C is the live palette – mutated in-place on theme toggle
_C = dict(_C_DARK)

_BROWSER_ACCENT = {
    "Brave":       "#fb542b",
    "Chrome":      "#4285f4",
    "Edge":        "#0078d4",
    "Tor Browser": "#7d4698",
}
_BASE_DIR  = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
_LOGO_PATH = os.path.join(_BASE_DIR, "logo.png")

def _open_logo(target_size=None):
    """Load logo.png, crop to icon square only, optionally resize. Returns PIL Image or None."""
    if not (_HAS_TRAY and os.path.exists(_LOGO_PATH)):
        return None
    try:
        img = _PilImage.open(_LOGO_PATH).convert("RGBA")
        w, h = img.size
        # Remove bottom ~24% (text/branding below the icon square)
        img = img.crop((0, 0, w, int(h * 0.76)))
        w, h = img.size
        # Remove outer dark margins (~11% sides, 7% top)
        mx, my = int(w * 0.11), int(h * 0.07)
        img = img.crop((mx, my, w - mx, h - my))
        # Center-crop to square
        w, h = img.size
        if w != h:
            s = min(w, h)
            img = img.crop(((w - s) // 2, (h - s) // 2,
                             (w - s) // 2 + s, (h - s) // 2 + s))
        if target_size:
            img = img.resize((target_size, target_size), _PilImage.LANCZOS)
        return img
    except Exception:
        return None

# --- 4. ANALYSIS POPUP WINDOW ---
class AnalysisWindow(ctk.CTkToplevel):
    def __init__(self, title, columns, data):
        super().__init__()
        self.title(title)
        self.geometry("1280x740")
        self.configure(fg_color=_C["bg"])
        self.attributes('-topmost', True)
        self.resizable(True, True)

        # ── header bar ──────────────────────────────────────────────────
        hdr = ctk.CTkFrame(self, fg_color=_C["surface"], corner_radius=0, height=52)
        hdr.pack(fill="x")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text=title, font=(_C["sans"], 14, "bold"),
                     text_color=_C["text"]).pack(side="left", padx=20, pady=14)
        ctk.CTkLabel(hdr, text=f"{len(data)} records",
                     font=(_C["sans"], 12), text_color=_C["text_dim"]).pack(side="right", padx=20)

        # ── treeview container ──────────────────────────────────────────
        frame = ctk.CTkFrame(self, fg_color=_C["surface2"], corner_radius=0)
        frame.pack(fill="both", expand=True, padx=0, pady=0)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("AR.Treeview",
                        background=_C["surface2"],
                        foreground=_C["text"],
                        fieldbackground=_C["surface2"],
                        rowheight=26,
                        borderwidth=0,
                        font=(_C["mono"], 11))
        style.configure("AR.Treeview.Heading",
                        background=_C["surface"],
                        foreground=_C["text_dim"],
                        relief="flat",
                        font=(_C["sans"], 10, "bold"))
        style.map("AR.Treeview",
                  background=[("selected", _C["accent_dim"])],
                  foreground=[("selected", _C["text"])])
        style.layout("AR.Treeview", [("AR.Treeview.treearea", {"sticky": "nswe"})])

        vsb = ttk.Scrollbar(frame, orient="vertical")
        hsb = ttk.Scrollbar(frame, orient="horizontal")
        self.tree = ttk.Treeview(frame, columns=columns, show="headings",
                                 style="AR.Treeview",
                                 yscrollcommand=vsb.set,
                                 xscrollcommand=hsb.set)
        vsb.configure(command=self.tree.yview)
        hsb.configure(command=self.tree.xview)

        for col in columns:
            self.tree.heading(col, text=col)
            self.tree.column(col, width=220, anchor="w", minwidth=80)

        # alternating row colours
        self.tree.tag_configure("odd",  background="#191919")
        self.tree.tag_configure("even", background=_C["surface2"])
        for i, row in enumerate(data):
            self.tree.insert("", "end", values=row, tags=("odd" if i % 2 else "even",))

        self.tree.grid(row=0, column=0, sticky="nsew")
        vsb.grid(row=0, column=1, sticky="ns")
        hsb.grid(row=1, column=0, sticky="ew")
        frame.grid_rowconfigure(0, weight=1)
        frame.grid_columnconfigure(0, weight=1)

# --- 5. MAIN DASHBOARD ---
class BrowsAR_App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Brows-AR  |  Browser Forensic Suite")
        self.geometry("1520x920")
        self.minsize(1100, 700)
        ctk.set_appearance_mode("dark")
        self.configure(fg_color=_C["bg"])

        self.current_browser_path = ""
        self.current_browser_name = ""
        self.physical_mode = False
        self.tab_offsets = {}
        self.page_size = 4096
        self.displays = {}
        self.last_results = []
        self.last_headers = []
        self._sidebar_btns = {}
        self._active_theme = "dark"
        self._tray_icon = None
        self._rebuilding = False
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<Unmap>", self._on_unmap)

        # ── sidebar ─────────────────────────────────────────────────────
        self._build_sidebar()

        # ── main canvas ─────────────────────────────────────────────────
        self.main_view = ctk.CTkFrame(self, corner_radius=0, fg_color=_C["bg"])
        self.main_view.pack(side="right", fill="both", expand=True)
        self._draw_welcome()
        if _HAS_TRAY:
            self.after(500, self._setup_tray)

    def _draw_welcome(self):
        for w in self.main_view.winfo_children():
            w.destroy()
        mid = ctk.CTkFrame(self.main_view, fg_color="transparent")
        mid.place(relx=0.5, rely=0.5, anchor="center")
        ctk.CTkLabel(mid, text="Brows-AR",
                     font=(_C["sans"], 48, "bold"),
                     text_color=_C["text_faint"]).pack()
        ctk.CTkLabel(mid, text="Select a target browser from the sidebar to begin.",
                     font=(_C["sans"], 14),
                     text_color=_C["text_faint"]).pack(pady=8)

    # ── sidebar builder (called on init and theme toggle) ──────────────
    def _build_sidebar(self):
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0,
                                    fg_color=_C["surface"])
        if hasattr(self, "main_view"):
            self.sidebar.pack(side="left", fill="y", before=self.main_view)
        else:
            self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        # logo block
        logo_frame = ctk.CTkFrame(self.sidebar, fg_color=_C["surface"], corner_radius=0)
        logo_frame.pack(fill="x", pady=(12, 16), padx=16)
        _logo_img = _open_logo(48)
        if _logo_img is not None:
            try:
                _ctk_logo = ctk.CTkImage(light_image=_logo_img, dark_image=_logo_img, size=(48, 48))
                ctk.CTkLabel(logo_frame, image=_ctk_logo, text="").pack(anchor="w", pady=(0, 6))
            except Exception:
                pass
        ctk.CTkLabel(logo_frame, text="Brows-AR",
                     font=(_C["sans"], 22, "bold"),
                     text_color=_C["text"]).pack(anchor="w")
        ctk.CTkLabel(logo_frame, text="Browser Forensic Suite",
                     font=(_C["sans"], 10),
                     text_color=_C["text_dim"]).pack(anchor="w")

        # divider
        ctk.CTkFrame(self.sidebar, height=1, fg_color=_C["border"],
                     corner_radius=0).pack(fill="x", padx=16, pady=(0, 16))

        ctk.CTkLabel(self.sidebar, text="TARGETS",
                     font=(_C["sans"], 9, "bold"),
                     text_color=_C["text_faint"]).pack(anchor="w", padx=20, pady=(0, 8))

        if not hasattr(self, "browser_paths"):
            self.browser_paths = {
                "Brave":  os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data"),
                "Chrome": os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data"),
                "Edge":   os.path.join(os.environ['LOCALAPPDATA'], r"Microsoft\Edge\User Data"),
            }
            _tor_root = find_tor_browser()
            if _tor_root:
                self.browser_paths["Tor Browser"] = _tor_root

        _icons = {"Brave": "🦁", "Chrome": "⬡", "Edge": "◈", "Tor Browser": "⬤"}
        self._sidebar_btns = {}
        for name, bpath in self.browser_paths.items():
            exists = os.path.exists(bpath)
            icon   = _icons.get(name, "▸")
            color  = _BROWSER_ACCENT.get(name, _C["accent"])
            is_active = (name == self.current_browser_name)
            btn = ctk.CTkButton(
                self.sidebar,
                text=f"  {icon}  {name}",
                anchor="w",
                height=40,
                corner_radius=8,
                font=(_C["sans"], 13),
                fg_color=color if is_active else "transparent",
                hover_color=_C["surface2"],
                text_color=_C["text"] if exists else _C["text_faint"],
                state="normal" if exists else "disabled",
                command=lambda n=name, p=bpath: self.load_browser_cockpit(n, p),
            )
            btn.pack(fill="x", padx=12, pady=3)
            self._sidebar_btns[name] = (btn, color)

        # ── theme toggle ────────────────────────────────────────────────
        ctk.CTkFrame(self.sidebar, height=1, fg_color=_C["border"],
                     corner_radius=0).pack(side="bottom", fill="x", padx=16)
        _theme_icon = "☀  Light Mode" if self._active_theme == "dark" else "🌙  Dark Mode"
        ctk.CTkButton(
            self.sidebar,
            text=_theme_icon,
            height=34,
            corner_radius=8,
            font=(_C["sans"], 12),
            fg_color=_C["surface2"],
            hover_color=_C["border"],
            text_color=_C["text_dim"],
            command=self._toggle_theme,
        ).pack(side="bottom", fill="x", padx=12, pady=(4, 10))

        ctk.CTkLabel(self.sidebar, text="v2.0  •  forensic mode",
                     font=(_C["sans"], 9),
                     text_color=_C["text_faint"]).pack(side="bottom", pady=(8, 4))

    def _toggle_theme(self):
        self._active_theme = "light" if self._active_theme == "dark" else "dark"
        _C.update(_C_LIGHT if self._active_theme == "light" else _C_DARK)
        ctk.set_appearance_mode("light" if self._active_theme == "light" else "dark")
        # defer rebuild so the button callback finishes before we destroy its parent
        self.after(10, self._apply_theme_rebuild)

    def _apply_theme_rebuild(self):
        self._rebuilding = True
        self.withdraw()               # hide window to prevent visible flicker
        self.sidebar.destroy()
        self._build_sidebar()
        self.configure(fg_color=_C["bg"])
        self.main_view.configure(fg_color=_C["bg"])
        if self.current_browser_name:
            self.load_browser_cockpit(self.current_browser_name, self.current_browser_path)
        else:
            self._draw_welcome()
        self.update_idletasks()        # flush all layout before revealing
        self.deiconify()               # show fully-rebuilt window at once
        self._rebuilding = False

    # ── system tray ──────────────────────────────────────────────────
    def _make_tray_img(self):
        """Tray icon: uses logo.png if available, else generated blue box."""
        logo = _open_logo(64)
        if logo is not None:
            return logo
        # fallback – generated blue rounded box with "AR"
        sz  = 64
        img = _PilImage.new("RGBA", (sz, sz), (0, 0, 0, 0))
        d   = _PilDraw.Draw(img)
        d.rounded_rectangle([0, 0, sz - 1, sz - 1], radius=10, fill="#4272d4")
        fnt = None
        for face in ("arialbd.ttf", "arial.ttf", "segoeui.ttf"):
            try:
                fnt = _PilFont.truetype(face, 28); break
            except Exception:
                pass
        txt = "AR"
        try:
            bbox = d.textbbox((0, 0), txt, font=fnt)
        except AttributeError:
            w, h = d.textsize(txt, font=fnt)  # Pillow < 8
            bbox = (0, 0, w, h)
        x = (sz - (bbox[2] - bbox[0])) // 2 - bbox[0]
        y = (sz - (bbox[3] - bbox[1])) // 2 - bbox[1]
        d.text((x, y), txt, fill="white", font=fnt)
        return img

    def _setup_tray(self):
        """Start pystray icon in background thread (runs for app lifetime)."""
        def _show(icon=None, item=None):
            self.after(0, self.deiconify)
            self.after(20, self.lift)

        def _quit(icon, item):
            if self._tray_icon:
                self._tray_icon.stop()
            self.after(0, self.destroy)

        menu = _pystray.Menu(
            _pystray.MenuItem("Show BrowsAR", _show, default=True),
            _pystray.Menu.SEPARATOR,
            _pystray.MenuItem("Quit", _quit),
        )
        self._tray_icon = _pystray.Icon(
            "BrowsAR", self._make_tray_img(),
            "Brows-AR  |  Browser Forensic Suite", menu,
        )
        _threading.Thread(target=self._tray_icon.run, daemon=True).start()

    def _on_close(self):
        """X button → hide to tray, do not destroy."""
        self.withdraw()

    def _on_unmap(self, event):
        """Minimize button → hide to tray."""
        if event.widget is self and not self._rebuilding:
            self.after(50, self._hide_if_iconic)

    def _hide_if_iconic(self):
        if self.state() == "iconic":
            self.withdraw()

    def load_browser_cockpit(self, name, path):
        self.current_browser_name, self.current_browser_path = name, path

        # highlight active sidebar button
        for bname, (btn, color) in self._sidebar_btns.items():
            btn.configure(fg_color=color if bname == name else "transparent")

        for widget in self.main_view.winfo_children():
            widget.destroy()

        accent = _BROWSER_ACCENT.get(name, _C["accent"])

        # ── top bar ─────────────────────────────────────────────────────
        topbar = ctk.CTkFrame(self.main_view, fg_color=_C["surface"],
                              corner_radius=0, height=60)
        topbar.pack(fill="x")
        topbar.pack_propagate(False)

        # coloured left accent strip
        ctk.CTkFrame(topbar, width=4, corner_radius=0,
                     fg_color=accent).pack(side="left", fill="y")

        ctk.CTkLabel(topbar, text=name,
                     font=(_C["sans"], 18, "bold"),
                     text_color=_C["text"]).pack(side="left", padx=18, pady=16)
        ctk.CTkLabel(topbar, text=path,
                     font=(_C["mono"], 10),
                     text_color=_C["text_dim"]).pack(side="left", padx=0)

        # right-side action buttons
        btn_frame = ctk.CTkFrame(topbar, fg_color="transparent")
        btn_frame.pack(side="right", padx=16)

        ctk.CTkButton(btn_frame, text="⤓  Export", width=100, height=32,
                      corner_radius=6,
                      font=(_C["sans"], 12),
                      fg_color=_C["surface2"], hover_color=_C["border"],
                      text_color=_C["text"],
                      command=self.export_evidence).pack(side="right", padx=4)

        ctk.CTkButton(btn_frame, text="▶  Run Analysis", width=140, height=32,
                      corner_radius=6,
                      font=(_C["sans"], 12, "bold"),
                      fg_color=accent, hover_color=accent,
                      text_color="white",
                      command=self.trigger_analysis).pack(side="right", padx=4)

        self.toggle_btn = ctk.CTkButton(
            btn_frame, text="▦  Relative", width=110, height=32,
            corner_radius=6,
            font=(_C["sans"], 12),
            fg_color=_C["surface2"], hover_color=_C["border"],
            text_color=_C["text_dim"],
            command=self.toggle_address_mode)
        self.toggle_btn.pack(side="right", padx=4)

        # ── custom tab bar ───────────────────────────────────────────────
        self._tab_frames     = {}
        self._tab_btns       = {}
        self._tab_indicators = {}
        self._active_tab     = None

        tabs = ["Hex Explorer", "Passwords", "History", "Downloads", "Bookmarks", "Autofill", "Registry", "Prefetch"]
        if name == "Brave":
            tabs.append("Cookies")
            tabs.append("TOR-Private")
        elif name in ("Chrome", "Edge"):
            tabs.append("Cookies")
        elif name == "Tor Browser":
            tabs = ["Hex Explorer", "Passwords", "History", "Downloads", "Bookmarks",
                    "Autofill", "Registry", "Prefetch", "Cookies", "Tor State"]

        # ── tab strip (scrollable) ───────────────────────────────────
        _strip_bg = _C["surface"]
        _tab_outer = ctk.CTkFrame(self.main_view, fg_color=_strip_bg,
                                  corner_radius=0, height=44)
        _tab_outer.pack(fill="x")
        _tab_outer.pack_propagate(False)

        # ◀ / ▶ scroll arrows pinned at the right edge
        _arrows = ctk.CTkFrame(_tab_outer, fg_color=_strip_bg, corner_radius=0)
        _arrows.pack(side="right", fill="y")
        # placeholder – wired to _tab_canvas after it's created
        _lbtn = ctk.CTkButton(_arrows, text="◀", width=28, height=44,
                              corner_radius=0,
                              font=(_C["sans"], 11),
                              fg_color="transparent",
                              hover_color=_C["surface2"],
                              text_color=_C["text_dim"])
        _lbtn.pack(side="left")
        _rbtn = ctk.CTkButton(_arrows, text="▶", width=28, height=44,
                              corner_radius=0,
                              font=(_C["sans"], 11),
                              fg_color="transparent",
                              hover_color=_C["surface2"],
                              text_color=_C["text_dim"])
        _rbtn.pack(side="left")

        _tab_canvas = _tk.Canvas(_tab_outer, height=44, bg=_strip_bg,
                                 highlightthickness=0, bd=0)
        _tab_canvas.pack(side="left", fill="both", expand=True)

        # wire arrow buttons now that canvas exists
        _lbtn.configure(command=lambda: _tab_canvas.xview_scroll(-3, "units"))
        _rbtn.configure(command=lambda: _tab_canvas.xview_scroll( 3, "units"))

        _tab_inner = _tk.Frame(_tab_canvas, bg=_strip_bg)
        _tab_canvas.create_window(0, 0, anchor="nw", window=_tab_inner)

        def _update_sr(e):
            _tab_canvas.configure(scrollregion=_tab_canvas.bbox("all"))
        _tab_inner.bind("<Configure>", _update_sr)

        def _wheel_h(e):
            _tab_canvas.xview_scroll(int(-1 * (e.delta / 120)), "units")
        _tab_canvas.bind("<MouseWheel>", _wheel_h)
        _tab_inner.bind("<MouseWheel>", _wheel_h)

        # thin separator below strip
        ctk.CTkFrame(self.main_view, height=1, fg_color=_C["border"],
                     corner_radius=0).pack(fill="x")

        # ── content area ────────────────────────────────────────────────
        self._tab_content_area = ctk.CTkFrame(self.main_view, fg_color=_C["bg"],
                                              corner_radius=0)
        self._tab_content_area.pack(fill="both", expand=True)

        # build ALL content frames first (none visible yet)
        for t in tabs:
            frame = ctk.CTkFrame(self._tab_content_area, fg_color=_C["bg"], corner_radius=0)
            self._tab_frames[t] = frame
            self.tab_offsets[t] = 0
            if t == "Registry":
                self.setup_registry_explorer(t)
            else:
                self.setup_hex_tab(t)

        # now render tab buttons (no layout work triggered above)
        _tab_icons = {
            "Hex Explorer": "⬡",
            "Passwords":    "🔑",
            "History":      "🕐",
            "Downloads":    "⬇",
            "Bookmarks":    "★",
            "Autofill":     "✏",
            "Registry":     "⚙",
            "Prefetch":     "⚡",
            "Cookies":      "◈",
            "TOR-Private":  "🧅",
            "Tor State":    "⬤",
        }
        for t in tabs:
            label = f" {_tab_icons.get(t, '')}  {t} "
            wrap = ctk.CTkFrame(_tab_inner, fg_color=_strip_bg, corner_radius=0)
            wrap.pack(side="left", fill="y")

            btn = ctk.CTkButton(
                wrap, text=label,
                height=38, corner_radius=0,
                font=(_C["sans"], 12),
                fg_color="transparent",
                hover_color=_C["surface2"],
                text_color=_C["text_dim"],
                border_width=0,
                command=lambda _t=t: self._switch_tab(_t),
            )
            btn.pack(fill="x", padx=0)

            ind = ctk.CTkFrame(wrap, height=2, corner_radius=0, fg_color="transparent")
            ind.pack(fill="x")

            # propagate scroll to canvas
            wrap.bind("<MouseWheel>", _wheel_h)
            btn.bind("<MouseWheel>", _wheel_h)

            self._tab_btns[t]       = btn
            self._tab_indicators[t] = ind

        # show first tab (no animation, instant)
        self._switch_tab(tabs[0])

    def toggle_address_mode(self):
        self.physical_mode = not self.physical_mode
        accent = _BROWSER_ACCENT.get(self.current_browser_name, _C["accent"])
        self.toggle_btn.configure(
            text="▩  Physical" if self.physical_mode else "▦  Relative",
            fg_color=accent if self.physical_mode else _C["surface2"],
            text_color=_C["text"] if self.physical_mode else _C["text_dim"])
        self.on_tab_changed()

    def _switch_tab(self, name):
        """Show content frame for the named tab, hide the previous one."""
        accent = _BROWSER_ACCENT.get(self.current_browser_name, _C["accent"])
        if self._active_tab and self._active_tab in self._tab_frames:
            self._tab_frames[self._active_tab].pack_forget()
            self._tab_btns[self._active_tab].configure(text_color=_C["text_dim"])
            self._tab_indicators[self._active_tab].configure(fg_color="transparent")
        self._active_tab = name
        self._tab_frames[name].pack(fill="both", expand=True)
        self._tab_btns[name].configure(text_color=_C["text"])
        self._tab_indicators[name].configure(fg_color=accent)
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
        container = ctk.CTkFrame(self._tab_frames[t], fg_color=_C["bg"], corner_radius=0)
        container.pack(fill="both", expand=True)

        txt = ctk.CTkTextbox(container,
                             font=(_C["mono"], 13),
                             wrap="none",
                             fg_color=_C["bg"],
                             text_color=_C["text"],
                             border_width=0,
                             scrollbar_button_color=_C["border"],
                             scrollbar_button_hover_color=_C["surface2"])
        txt.pack(fill="both", expand=True, padx=0, pady=0)
        self.displays[t] = txt

        nav = ctk.CTkFrame(container, fg_color=_C["surface"], corner_radius=0, height=44)
        nav.pack(fill="x", side="bottom")
        nav.pack_propagate(False)

        accent = _BROWSER_ACCENT.get(self.current_browser_name, _C["accent"])
        ctk.CTkButton(nav, text="← Prev", width=90, height=28,
                      corner_radius=5,
                      font=(_C["sans"], 12),
                      fg_color=_C["surface2"], hover_color=_C["border"],
                      text_color=_C["text"],
                      command=lambda tab=t: self.change_page(tab, -1)).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(nav, text="Next →", width=90, height=28,
                      corner_radius=5,
                      font=(_C["sans"], 12),
                      fg_color=_C["surface2"], hover_color=_C["border"],
                      text_color=_C["text"],
                      command=lambda tab=t: self.change_page(tab, 1)).pack(side="right", padx=12, pady=8)

    def setup_registry_explorer(self, t):
        container = ctk.CTkFrame(self._tab_frames[t], fg_color=_C["bg"], corner_radius=0)
        container.pack(fill="both", expand=True)

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("Reg.Treeview",
                        background=_C["surface"],
                        foreground=_C["text"],
                        fieldbackground=_C["surface"],
                        rowheight=24,
                        borderwidth=0,
                        font=(_C["mono"], 11))
        style.configure("Reg.Treeview.Heading",
                        background=_C["surface2"],
                        foreground=_C["text_dim"],
                        relief="flat",
                        font=(_C["sans"], 10, "bold"))
        style.map("Reg.Treeview",
                  background=[("selected", _C["accent_dim"])],
                  foreground=[("selected", _C["text"])])

        # Use classic tk PanedWindow so bg colour is respected
        pane = _tk.PanedWindow(container, orient=_tk.HORIZONTAL,
                               bg=_C["bg"], sashwidth=4,
                               sashrelief="flat", bd=0)
        pane.pack(fill="both", expand=True)

        left_frame  = ctk.CTkFrame(pane, fg_color=_C["surface"], corner_radius=0)
        right_frame = ctk.CTkFrame(pane, fg_color=_C["surface2"], corner_radius=0)
        pane.add(left_frame,  width=360, minsize=120)
        pane.add(right_frame, minsize=200)

        # key tree
        ctk.CTkLabel(left_frame, text="Registry Keys",
                     font=(_C["sans"], 10, "bold"),
                     text_color=_C["text_dim"]).pack(anchor="w", padx=12, pady=(10, 4))
        self.reg_tree = ttk.Treeview(left_frame, show="tree", style="Reg.Treeview")
        vsb_l = ttk.Scrollbar(left_frame, orient="vertical", command=self.reg_tree.yview)
        self.reg_tree.configure(yscrollcommand=vsb_l.set)
        self.reg_tree.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=(0, 8))
        vsb_l.pack(side="right", fill="y", pady=(0, 8))
        self.reg_tree.bind("<<TreeviewSelect>>", self.on_registry_key_selected)

        # value panel
        ctk.CTkLabel(right_frame, text="Values",
                     font=(_C["sans"], 10, "bold"),
                     text_color=_C["text_dim"]).pack(anchor="w", padx=12, pady=(10, 4))
        self.reg_values = ttk.Treeview(right_frame, columns=("Name", "Data"),
                                       show="headings", style="Reg.Treeview")
        self.reg_values.heading("Name", text="Property")
        self.reg_values.heading("Data", text="Value")
        self.reg_values.column("Name", width=180, minwidth=80)
        self.reg_values.column("Data", width=400, minwidth=100)
        vsb_r = ttk.Scrollbar(right_frame, orient="vertical", command=self.reg_values.yview)
        self.reg_values.configure(yscrollcommand=vsb_r.set)
        self.reg_values.pack(side="left", fill="both", expand=True, padx=(8, 0), pady=(0, 8))
        vsb_r.pack(side="right", fill="y", pady=(0, 8))
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
        elif self.current_browser_name == "Tor Browser":
            return [
                (winreg.HKEY_CURRENT_USER,
                 r"Software\Microsoft\Windows\CurrentVersion\Explorer"
                 r"\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"),
                (winreg.HKEY_CURRENT_USER,
                 r"Software\Classes\Local Settings\Software\Microsoft"
                 r"\Windows\Shell\MuiCache"),
                (winreg.HKEY_CURRENT_USER,
                 r"Software\Microsoft\Windows\CurrentVersion\Uninstall\Tor Browser"),
            ]
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
        active = self._active_tab
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
        # --- 0. TOR BROWSER (Firefox-based, completely different layout) ---
        if self.current_browser_name == "Tor Browser":
            profile = self._get_tor_browser_profile()
            tor_data_dir = os.path.join(self.current_browser_path,
                                        "Browser", "TorBrowser", "Data", "Tor")
            mapping = {
                "Hex Explorer": os.path.join(profile, "prefs.js") if profile else None,
                "Passwords":    os.path.join(profile, "key4.db")  if profile else None,
                "History":      os.path.join(profile, "places.sqlite") if profile else None,
                "Downloads":    os.path.join(profile, "places.sqlite") if profile else None,
                "Bookmarks":    os.path.join(profile, "places.sqlite") if profile else None,
                "Autofill":     os.path.join(profile, "content-prefs.sqlite") if profile else None,
                "Cookies":      os.path.join(profile, "cookies.sqlite") if profile else None,
                "Tor State":    os.path.join(tor_data_dir, "state"),
                "Registry":     None,
                "Prefetch":     None,
            }
            return mapping.get(active)

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
        tab = self._active_tab
        # --- Tor Browser (Firefox-based) has its own analysis methods ---
        if self.current_browser_name == "Tor Browser":
            if   tab == "History":   self.analyze_tor_browser_history()
            elif tab == "Downloads": self.analyze_tor_browser_downloads()
            elif tab == "Bookmarks": self.analyze_tor_browser_bookmarks()
            elif tab == "Autofill":  self.analyze_tor_browser_autofill()
            elif tab == "Cookies":   self.analyze_tor_browser_cookies()
            elif tab == "Passwords": self.analyze_tor_browser_passwords()
            elif tab == "Registry":  self.analyze_tor_browser_registry()
            elif tab == "Prefetch":  self.analyze_tor_browser_prefetch()
            elif tab == "Tor State": self.analyze_tor_browser_state()
            return
        if tab == "Passwords": self.analyze_passwords()
        elif tab == "History": self.analyze_history()
        elif tab == "Downloads": self.analyze_downloads()
        elif tab == "Bookmarks": self.analyze_bookmarks()
        elif tab == "Autofill": self.analyze_autofill()
        elif tab == "Registry": self.analyze_registry_deep()
        elif tab == "Prefetch": self.analyze_prefetch_deep()
        elif tab == "Cookies":
            if self.current_browser_name == "Brave": self.analyze_brave_cookies()
            elif self.current_browser_name == "Chrome": self.analyze_chrome_cookies()
            elif self.current_browser_name == "Edge": self.analyze_edge_cookies()
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
    # ------------------------------------------------------------------ #
    #  TIER-1 HELPERS  (called from analyze_tor_private)                 #
    # ------------------------------------------------------------------ #

    def _tor_scan_amcache(self):
        """
        Amcache — records first-execution path and timestamp for every executable.
        Survives Brave/Tor uninstall entirely.
        Windows keeps InventoryApplicationFile live under HKLM so we query it
        directly (no hive loading needed, no SYSTEM requirement).
        Falls back to a filesystem search of the hive for any 'tor' string if
        the live key is unavailable.
        """
        res = []

        # --- Live registry path (Windows 8.1+, always accessible as admin) ---
        live_root = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Amcache\InventoryApplicationFile"
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, live_root,
                                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as root:
                count = winreg.QueryInfoKey(root)[0]
                for i in range(count):
                    try:
                        subkey_name = winreg.EnumKey(root, i)
                        with winreg.OpenKey(root, subkey_name,
                                            0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as sk:
                            def _val(k, default="N/A"):
                                try:
                                    return winreg.QueryValueEx(sk, k)[0]
                                except OSError:
                                    return default
                            name = _val("Name")
                            path = _val("LowerCaseLongPath")
                            sha1 = _val("FileId")
                            link_date = _val("LinkDate")
                            if "tor" not in name.lower() and "tor" not in path.lower():
                                continue
                            sha1_clean = sha1[4:] if isinstance(sha1, str) and sha1.startswith("0000") else sha1
                            res.append(("Amcache | First-Run Path", path))
                            res.append(("Amcache | File Name", name))
                            res.append(("Amcache | SHA-1 Hash", sha1_clean))
                            res.append(("Amcache | Link Date", link_date))
                    except OSError:
                        continue
        except OSError:
            # Live key not present — fall back to binary grep of the hive file
            hive = r"C:\Windows\AppCompat\Programs\Amcache.hve"
            if os.path.exists(hive):
                try:
                    with open(hive, "rb") as f:
                        raw = f.read()
                    text = raw.decode("utf-16-le", errors="ignore")
                    import re as _re
                    for m in _re.finditer(r'[a-zA-Z]:\\[^\x00\r\n]{4,200}[Tt][Oo][Rr][^\x00\r\n]{0,80}', text):
                        res.append(("Amcache (raw grep) | Path", m.group(0).strip()))
                except OSError:
                    res.append(("Amcache", "Hive file locked and live key unavailable"))
            else:
                res.append(("Amcache", "InventoryApplicationFile key not found (requires Win8.1+)"))

        if not res:
            res.append(("Amcache", "No tor-related entries found"))
        return res

    def _tor_scan_shimcache(self):
        """
        AppCompatCache (ShimCache) — logs every executable that touched the
        filesystem.  Proves tor.exe existed at a path even after deletion.
        The blob is a Windows 10/11 SHIM cache: 128-byte header followed by
        variable-length entries.  Each entry contains a UTF-16LE path.
        We extract paths using a regex on the raw blob to avoid full format
        parsing while still producing clean results.
        """
        res = []
        import re as _re
        try:
            reg_path = r"SYSTEM\CurrentControlSet\Control\Session Manager\AppCompatCache"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path,
                                0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                raw, _ = winreg.QueryValueEx(key, "AppCompatCache")

            # Extract clean Windows paths from the binary blob.
            # Strategy: find sequences of UTF-16LE characters that form a valid
            # drive-letter path (e.g. C:\...) by scanning the raw bytes for the
            # pattern [A-Z]: (0x3A 0x00 follows the drive letter in UTF-16LE).
            # Each path ends at the first non-path byte pair.
            path_pattern = _re.compile(
                rb'(?:[A-Za-z]\x00:\x00\\\x00)(?:[^\x00\x01-\x1f]\x00){4,255}'
            )
            # Only keep paths genuinely tor-related:
            # filename is tor.exe, or path contains tor-browser/torbrowser/\Tor\
            import re as _re_sc
            tor_relevant = _re_sc.compile(
                r'(?i)(?:[/\\]tor\.exe$|tor[\s_-]browser|torbrowser|[/\\][Tt]or[/\\])'
            )
            for m in path_pattern.finditer(raw):
                try:
                    path = m.group(0).decode("utf-16-le", errors="ignore").rstrip("\x00").strip()
                    if tor_relevant.search(path) and len(path) > 6:
                        res.append(("ShimCache | Executable Path", path))
                except Exception:
                    continue

        except OSError as ex:
            res.append(("ShimCache", f"Access error: {ex}"))
            return res

        if not res:
            res.append(("ShimCache", "No tor-related executables found in AppCompatCache"))
        return res

    def _tor_scan_eventlog(self):
        """
        Windows Security Event Log — Event ID 4688 (Process Creation).
        Requires 'Audit Process Creation' policy to be enabled on the system.
        Uses wevtutil to query without needing the win32evtlog library.
        """
        res = []
        cmd = (
            'wevtutil qe Security '
            '/q:"*[System[EventID=4688]] and *[EventData[Data[@Name=\'NewProcessName\'] and contains(.,\'tor\')]]" '
            '/f:text /rd:true /c:50'
        )
        try:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.DEVNULL,
                                          timeout=15).decode("utf-8", errors="ignore")
            if out.strip():
                for line in out.splitlines():
                    line = line.strip()
                    if any(k in line for k in ("Date", "New Process Name", "Creator Process",
                                               "Account Name", "Process ID")):
                        res.append(("Event Log (4688)", line))
            else:
                res.append(("Event Log (4688)", "No process-creation events for tor.exe found"))
        except subprocess.TimeoutExpired:
            res.append(("Event Log (4688)", "Query timed out"))
        except subprocess.CalledProcessError:
            res.append(("Event Log (4688)", "Access denied or audit policy not enabled"))
        return res

    # ------------------------------------------------------------------ #
    #  TIER-2 HELPERS                                                     #
    # ------------------------------------------------------------------ #

    def _tor_scan_preferences_onion(self):
        """
        Brave Preferences — full-text grep for ANY .onion reference across the
        entire JSON, plus brave.tor.* config keys.  Scanning just
        content_settings.exceptions misses most cases because Brave only writes
        there when the user explicitly grants a site permission.
        """
        import re as _re_p
        onion_re = _re_p.compile(r'[a-z2-7]{16,56}\.onion(?:/[^\s"<>]{0,80})?')
        res = []
        prefs_file = os.path.join(self.current_browser_path, "Default", "Preferences")
        if not os.path.exists(prefs_file):
            return [("Preferences", "Default/Preferences not found")]

        tmp = "prefs_tor_scan_tmp.json"
        try:
            shutil.copyfile(prefs_file, tmp)
            with open(tmp, "r", encoding="utf-8") as f:
                raw_text = f.read()
            prefs = json.loads(raw_text)

            # Full-text grep — catches any key/value containing an onion address
            found_onion = sorted(set(m.group(0) for m in onion_re.finditer(raw_text)))
            if found_onion:
                for addr in found_onion:
                    res.append(("Preferences | Onion Address", addr))
            else:
                res.append(("Preferences Onion Scan", "No .onion addresses found in Preferences"))

            # brave.tor.* configuration keys
            brave_tor = prefs.get("brave", {}).get("tor", {})
            if brave_tor:
                for k, v in brave_tor.items():
                    res.append((f"Brave Tor Config | {k}", str(v)))
            else:
                res.append(("Brave Tor Config", "No brave.tor keys in Preferences"))

            # Top-level tor_disabled flag
            tor_disabled = prefs.get("brave", {}).get("tor_disabled", None)
            if tor_disabled is not None:
                res.append(("Brave Tor Disabled Flag", str(tor_disabled)))

        except Exception as e:
            res.append(("Preferences Scan Error", str(e)))
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
        return res

    def _tor_scan_tor_data_dir(self):
        """
        Scans two sources for .onion evidence:
        1. Brave's internal Tor data directory (User Data\\tor\\data) — contains
           guard node state, cached circuits, and Tor's own runtime files.
        2. Binary-greps EVERY Brave profile's session files for .onion URLs.
           Brave Tor windows may write to a separate profile sub-directory, so
           we scan all profile dirs (Default, Profile 1, etc.) instead of only
           Default.
        """
        import re as _re_t
        onion_re = _re_t.compile(r'[a-z2-7]{16,56}\.onion(?:/[^\x00\s"<>]{0,80})?')
        res = []

        # --- 1. Tor internal data directory ---
        tor_data = os.path.join(self.current_browser_path, "tor", "data")
        if os.path.exists(tor_data):
            for root_d, dirs, files in os.walk(tor_data):
                for fname in files:
                    fpath = os.path.join(root_d, fname)
                    try:
                        stat = os.stat(fpath)
                        rel = os.path.relpath(fpath, tor_data)
                        res.append(("Tor Data Dir | File",
                                    f"{rel}  ({stat.st_size}B  "
                                    f"mod:{datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')})"))
                        if stat.st_size < 512 * 1024:
                            with open(fpath, "rb") as f:
                                content = f.read().decode("latin-1", errors="ignore")
                            for m in onion_re.finditer(content):
                                res.append((f"Tor Data | {fname} | Onion Ref", m.group(0)))
                    except OSError:
                        pass
        else:
            res.append(("Tor Data Directory",
                        "Not found — Brave Tor window not yet used, or data was cleared"))

        # --- 2. Session files across ALL profile directories ---
        session_files = ["Last Session", "Last Tabs", "Current Session", "Current Tabs"]
        found_any_onion = False
        try:
            for entry in os.listdir(self.current_browser_path):
                profile_dir = os.path.join(self.current_browser_path, entry)
                if not os.path.isdir(profile_dir):
                    continue
                for sfile in session_files:
                    fpath = os.path.join(profile_dir, sfile)
                    if not os.path.exists(fpath):
                        continue
                    try:
                        with open(fpath, "rb") as f:
                            raw = f.read()
                        text = raw.decode("latin-1", errors="ignore")
                        for m in onion_re.finditer(text):
                            res.append((f"Session | {entry}/{sfile}", m.group(0)))
                            found_any_onion = True
                    except OSError:
                        pass
        except OSError:
            pass

        if not found_any_onion:
            res.append(("Session/Profile Onion Scan",
                        "No .onion addresses found in any profile session file"))
        return res

    # ------------------------------------------------------------------ #
    #  MASTER TOR ANALYZER                                                #
    # ------------------------------------------------------------------ #

    def analyze_tor_private(self):
        """Master Tor Forensic Engine — Tier 1 & 2 artifact extraction."""
        res = []

        # --- Component presence ---
        comp = os.path.join(self.current_browser_path, "cpoalefficncklhjfpglfiplenlpccdb")
        if os.path.exists(comp):
            m_time = datetime.datetime.fromtimestamp(os.path.getmtime(comp))
            res.append(("Tor Plugin Status", f"INSTALLED/INITIALIZED: {m_time}"))

        # --- 1. Prefetch execution timeline ---
        pf_dir = r"C:\Windows\Prefetch"
        if os.path.exists(pf_dir):
            for f in os.listdir(pf_dir):
                if "TOR" in f.upper() and f.endswith(".pf"):
                    times = get_prefetch_history(os.path.join(pf_dir, f))
                    for i, t in enumerate(times):
                        res.append((f"Prefetch Exec Time {i+1}", t))

        # --- 2. Bridge & network volume (tor-torrc + state file) ---
        tor_comp = os.path.join(self.current_browser_path, "cpoalefficncklhjfpglfiplenlpccdb")
        if os.path.exists(tor_comp):
            for root, dirs, files in os.walk(tor_comp):
                if "tor-torrc" in files:
                    res.extend(self.get_tor_network_artifacts(root))

        # --- 3. UserAssist registry (ROT-13 decoded) ---
        try:
            ua_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_path) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    n, d, _ = winreg.EnumValue(key, i)
                    decoded = rot13(n)
                    if "tor" in decoded.lower():
                        res.append(("UserAssist Registry", f"{decoded} (Runs: {struct.unpack('<I', d[4:8])[0]})"))
        except Exception:
            pass

        # ============================================================== #
        #  TIER 1 — Prove Tor was used (survives uninstall)              #
        # ============================================================== #
        res.append(("--- TIER 1: PERSISTENCE EVIDENCE ---", ""))

        res.extend(self._tor_scan_amcache())
        res.extend(self._tor_scan_shimcache())
        res.extend(self._tor_scan_eventlog())

        # ============================================================== #
        #  TIER 2 — Prove what sites were visited                        #
        # ============================================================== #
        res.append(("--- TIER 2: VISITED SITES EVIDENCE ---", ""))

        res.extend(self._tor_scan_preferences_onion())
        res.extend(self._tor_scan_tor_data_dir())

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
        exe_map = {
            "Brave":   ["BRAVE.EXE"],
            "Chrome":  ["CHROME.EXE"],
            "Edge":    ["MSEDGE.EXE"],
        }
        exe_names = exe_map.get(self.current_browser_name, [])
        pf_dir, res = r"C:\Windows\Prefetch", []
        if not os.path.exists(pf_dir):
            self.last_results, self.last_headers = [("Prefetch", "Prefetch disabled")], ["Artifact", "Data"]
            AnalysisWindow("Prefetch", self.last_headers, self.last_results)
            return

        for exe in exe_names:
            for f in os.listdir(pf_dir):
                if f.upper().startswith(exe) and f.endswith(".pf"):
                    path = os.path.join(pf_dir, f)
                    stat = os.stat(path)
                    with open(path, "rb") as fd:
                        h = fd.read(8)
                    info = (f"MAM Compressed | {datetime.datetime.fromtimestamp(stat.st_mtime)}"
                            if h[0:3] == b'MAM' else "SCCA Standard")
                    res.append((f, info))
        self.last_results, self.last_headers = res, ["Artifact", "Data"]
        AnalysisWindow("Prefetch", self.last_headers, res)

    def _cdp_extract_cookies(self, browser_name, exe_path, process_name, user_data_dir):
        """Generic CDP cookie extractor. Launches the browser headless, pulls all cookies via
        Network.getAllCookies, kills the browser, and returns the result rows."""
        messagebox.showinfo("Brows-AR", f"Starting Headless Bypass. {browser_name} will close temporarily.")
        subprocess.run(f"taskkill /F /IM {process_name} /T", shell=True, capture_output=True)
        time.sleep(2)
        cmd = f'"{exe_path}" --remote-debugging-port=9222 --user-data-dir="{user_data_dir}" --remote-allow-origins=* --headless --disable-gpu --no-sandbox'
        subprocess.Popen(cmd, shell=True)
        time.sleep(5)
        try:
            resp = requests.get("http://localhost:9222/json", timeout=10)
            targets = resp.json()
            if not targets:
                messagebox.showerror("CDP Error", "No debuggable targets found.")
                return
            ws_url = targets[0]['webSocketDebuggerUrl']
            ws = websocket.create_connection(ws_url, timeout=10)
            ws.send(json.dumps({"id": 1, "method": "Network.getAllCookies"}))
            result = json.loads(ws.recv())
            cookies = result.get('result', {}).get('cookies', [])
            ws.close()
            subprocess.run(f"taskkill /F /IM {process_name} /T", shell=True, capture_output=True)
            res = [(c['domain'], c['name'], c['value'][:50] + ("..." if len(c['value']) > 50 else "")) for c in cookies]
            self.last_results, self.last_headers = res, ["Domain", "Name", "Value"]
            AnalysisWindow(f"{browser_name} Cookies (CDP Bypass)", self.last_headers, res)
        except Exception as e:
            subprocess.run(f"taskkill /F /IM {process_name} /T", shell=True, capture_output=True)
            messagebox.showerror("Bypass Failed", f"Error: {e}")

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

    def analyze_chrome_cookies(self):
        """
        Direct SQLite + two-stage DPAPI decryption — no CDP / headless launch needed.
        Chrome refuses to bind the remote-debugging port when the parent process is
        elevated (admin), so the CDP approach is fundamentally broken on this tool.
        Instead we replicate the same master-key extraction used for passwords and
        decrypt each cookie's encrypted_value directly from the SQLite database.
        """
        try:
            # 1. Load Local State and extract master key (identical to analyze_passwords)
            ls_path = self.get_artifact_path("Hex Explorer")  # resolves to "Local State"
            if not ls_path:
                messagebox.showerror("Forensic Error", "Could not locate Chrome Local State.")
                return
            with open(ls_path, "r", encoding="utf-8") as f:
                ls = json.load(f)

            os_crypt = ls.get("os_crypt", {})
            if "app_bound_encrypted_key" in os_crypt:
                raw_key = base64.b64decode(os_crypt["app_bound_encrypted_key"])[4:]
                s1 = None
                if impersonate_system():
                    try:
                        s1 = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
                    finally:
                        win32security.RevertToSelf()
                if s1 is None:
                    messagebox.showerror("Forensic Error", "SYSTEM impersonation failed; cannot decrypt Chrome cookies.")
                    return
                final_key = win32crypt.CryptUnprotectData(s1, None, None, None, 0)[1][-32:]
            else:
                final_key = win32crypt.CryptUnprotectData(
                    base64.b64decode(os_crypt["encrypted_key"])[5:], None, None, None, 0)[1]

            # 2. Copy and query the Cookies SQLite database
            cookie_path = self.get_artifact_path("Cookies")
            if not cookie_path:
                messagebox.showerror("Forensic Error", "Could not locate Chrome Cookies database.")
                return
            temp_db = "temp_chrome_cookies.db"
            shutil.copyfile(cookie_path, temp_db)
            res = []
            try:
                conn = sqlite3.connect(temp_db)
                cur = conn.cursor()
                cur.execute("SELECT host_key, name, encrypted_value FROM cookies")
                for host, name, enc_val in cur.fetchall():
                    try:
                        iv = enc_val[3:15]
                        payload = enc_val[15:]
                        ciphertext, tag = payload[:-16], payload[-16:]
                        cipher = AES.new(final_key, AES.MODE_GCM, iv)
                        value = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8", errors="ignore")
                    except Exception:
                        value = "[Encrypted]"
                    display_val = value[:50] + ("..." if len(value) > 50 else "")
                    res.append((host, name, display_val))
                conn.close()
            finally:
                try:
                    os.remove(temp_db)
                except OSError:
                    pass

            self.last_results, self.last_headers = res, ["Domain", "Name", "Value"]
            AnalysisWindow("Chrome Cookies (Direct Decrypt)", self.last_headers, res)

        except Exception as e:
            messagebox.showerror("Forensic Error", str(e))

    def analyze_edge_cookies(self):
        _edge_candidates = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]
        edge_exe = next((p for p in _edge_candidates if os.path.exists(p)), _edge_candidates[0])
        self._cdp_extract_cookies("Edge", edge_exe, "msedge.exe", self.current_browser_path)

    # ================================================================== #
    #  TOR BROWSER FORENSIC METHODS                                      #
    # ================================================================== #

    def _get_tor_browser_profile(self):
        """Return the active Tor Browser profile directory, or None."""
        base = os.path.join(self.current_browser_path,
                            "Browser", "TorBrowser", "Data", "Browser")
        std = os.path.join(base, "profile.default")
        if os.path.exists(std):
            return std
        if os.path.exists(base):
            for entry in os.listdir(base):
                if entry.startswith("profile") and os.path.isdir(os.path.join(base, entry)):
                    return os.path.join(base, entry)
        return None

    def analyze_tor_browser_history(self):
        from tor_history import get_tor_history
        profile = self._get_tor_browser_profile()
        if not profile:
            messagebox.showerror("Forensic Error", "Tor Browser profile not found.")
            return
        res = get_tor_history(profile)
        self.last_results, self.last_headers = res, ["URL", "Title", "Visits", "Last Visit"]
        AnalysisWindow("Tor Browser — Browsing History", self.last_headers, res)

    def analyze_tor_browser_downloads(self):
        from tor_downloads import get_tor_downloads
        profile = self._get_tor_browser_profile()
        if not profile:
            messagebox.showerror("Forensic Error", "Tor Browser profile not found.")
            return
        res = get_tor_downloads(profile)
        self.last_results, self.last_headers = res, ["Source URL", "Local Path", "Time", "Size", "Status"]
        AnalysisWindow("Tor Browser — Download History", self.last_headers, res)

    def analyze_tor_browser_bookmarks(self):
        from tor_bookmarks import get_tor_bookmarks
        profile = self._get_tor_browser_profile()
        if not profile:
            messagebox.showerror("Forensic Error", "Tor Browser profile not found.")
            return
        res = get_tor_bookmarks(profile)
        self.last_results, self.last_headers = res, ["Title", "URL", "Date Added", "Last Modified"]
        AnalysisWindow("Tor Browser — Bookmarks", self.last_headers, res)

    def analyze_tor_browser_autofill(self):
        from tor_autofill import get_tor_autofill
        profile = self._get_tor_browser_profile()
        if not profile:
            messagebox.showerror("Forensic Error", "Tor Browser profile not found.")
            return
        res = get_tor_autofill(profile)
        self.last_results, self.last_headers = res, ["Source", "Key / Site", "Value / Setting", "Details"]
        AnalysisWindow("Tor Browser — Autofill & Site Preferences", self.last_headers, res)

    def analyze_tor_browser_cookies(self):
        from tor_cookies import get_tor_cookies
        profile = self._get_tor_browser_profile()
        if not profile:
            messagebox.showerror("Forensic Error", "Tor Browser profile not found.")
            return
        res = get_tor_cookies(profile)
        self.last_results, self.last_headers = res, ["Host", "Name", "Value", "Path", "Last Accessed", "Flags"]
        AnalysisWindow("Tor Browser — Cookies", self.last_headers, res)

    def analyze_tor_browser_passwords(self):
        from tor_passwords import get_tor_passwords
        profile = self._get_tor_browser_profile()
        if not profile:
            messagebox.showerror("Forensic Error", "Tor Browser profile not found.")
            return
        res = get_tor_passwords(profile, self.current_browser_path)
        self.last_results, self.last_headers = res, ["URL", "Username", "Password"]
        AnalysisWindow("Tor Browser — Credentials (NSS)", self.last_headers, res)

    def analyze_tor_browser_registry(self):
        from tor_registry import get_tor_registry
        res = get_tor_registry()
        self.last_results, self.last_headers = res, ["Registry Artifact", "Value"]
        AnalysisWindow("Tor Browser — Registry Artifacts", self.last_headers, res)

    def analyze_tor_browser_prefetch(self):
        from tor_prefetch import get_tor_prefetch
        res = get_tor_prefetch()
        self.last_results, self.last_headers = res, ["Artifact", "Value"]
        AnalysisWindow("Tor Browser — Prefetch Evidence", self.last_headers, res)

    def analyze_tor_browser_state(self):
        """
        Parse Tor daemon config, state file, onion-aliases, and session store.
        This is the richest forensic source for Tor Browser — the state file
        contains guard node RSA fingerprints, bridge IP:port pairs, and the
        exact timestamps of every Tor session on this machine.
        """
        import re as _re
        res = []
        profile   = self._get_tor_browser_profile()
        tor_data  = os.path.join(self.current_browser_path,
                                 "Browser", "TorBrowser", "Data", "Tor")
        browser_dir = os.path.join(self.current_browser_path, "Browser")

        # --- Tor Browser version ---
        for ini in ("application.ini",
                    os.path.join("TorBrowser", "Data", "Browser", "application.ini")):
            ini_path = os.path.join(browser_dir, ini)
            if os.path.exists(ini_path):
                try:
                    with open(ini_path, "r", encoding="utf-8") as f:
                        for line in f:
                            if line.startswith(("Version=", "BuildID=")):
                                k, v = line.strip().split("=", 1)
                                res.append((f"Tor Browser | {k}", v))
                except OSError:
                    pass
                break

        # --- torrc configuration ---
        torrc_path = os.path.join(tor_data, "torrc")
        if os.path.exists(torrc_path):
            try:
                with open(torrc_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            res.append(("torrc | Config", line))
            except OSError:
                res.append(("torrc", "Read error"))
        else:
            res.append(("torrc", "Not found — Tor daemon not yet initialised"))

        # --- state file (guard nodes, bridges, bandwidth, timestamps) ---
        state_path = os.path.join(tor_data, "state")
        if os.path.exists(state_path):
            stat = os.stat(state_path)
            res.append(("State File | Size",
                         f"{stat.st_size} bytes"))
            res.append(("State File | Last Modified",
                         datetime.datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')))
            try:
                with open(state_path, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#"):
                            continue
                        kw = line.split()[0] if line.split() else ""
                        if kw in ("Guard", "TotalWriteBytes", "TotalReadBytes",
                                  "LastWritten", "MinutesSinceUserActivity",
                                  "TorVersion", "Dormant", "TotalBuildTimes"):
                            res.append((f"State | {kw}", line))
            except OSError:
                pass
        else:
            res.append(("State File",
                         "Not found — Tor connection never established on this machine"))

        # --- All files in Tor data directory ---
        if os.path.exists(tor_data):
            res.append(("--- Tor Data Directory ---", tor_data))
            for fname in sorted(os.listdir(tor_data)):
                fpath = os.path.join(tor_data, fname)
                if os.path.isfile(fpath):
                    try:
                        s = os.stat(fpath)
                        res.append(("Tor Data | File",
                                     f"{fname}  ({s.st_size}B  "
                                     f"mod:{datetime.datetime.fromtimestamp(s.st_mtime).strftime('%Y-%m-%d %H:%M:%S')})"))
                    except OSError:
                        pass

        # --- onion-aliases.json (SecureDrop .onion alias database) ---
        if profile:
            aliases_path = os.path.join(profile, "onion-aliases.json")
            if os.path.exists(aliases_path):
                try:
                    with open(aliases_path, "r", encoding="utf-8") as f:
                        aliases = json.load(f)
                    res.append(("Onion Aliases | Last Check",
                                 str(aliases.get("lastCheck", "N/A"))))
                    for ch in aliases.get("channels", []):
                        res.append(("Onion Aliases | Channel", ch.get("name", "?")))
                        res.append(("Onion Aliases | Scope", ch.get("scope", "?")))
                        for m in ch.get("mappings", []):
                            res.append(("Onion Aliases | Mapping",
                                         f"{m.get('from', '?')}  →  {m.get('to', '?')}"))
                except Exception as e:
                    res.append(("Onion Aliases | Error", str(e)))

        # --- sessionstore.jsonlz4 (last session tabs, may contain .onion URLs) ---
        if profile:
            ss_path = os.path.join(profile, "sessionstore.jsonlz4")
            if os.path.exists(ss_path):
                try:
                    import lz4.block as _lz4
                    with open(ss_path, "rb") as f:
                        magic = f.read(8)       # b'mozLz40\x00'
                        orig_len = struct.unpack("<I", f.read(4))[0]
                        compressed = f.read()
                    raw_json = _lz4.decompress(compressed, uncompressed_size=orig_len)
                    session = json.loads(raw_json.decode("utf-8"))
                    onion_re = _re.compile(r'[a-z2-7]{16,56}\.onion(?:/[^\s"<>]{0,80})?')
                    found = set()
                    for win in session.get("windows", []):
                        for tab in win.get("tabs", []):
                            for entry in tab.get("entries", []):
                                url = entry.get("url", "")
                                res.append(("Session Tab", url))
                                for m in onion_re.finditer(url):
                                    found.add(m.group(0))
                    for addr in sorted(found):
                        res.append(("Session | Onion Address", addr))
                    if not found:
                        res.append(("Session Onion Scan", "No .onion addresses in last session"))
                except ImportError:
                    res.append(("sessionstore.jsonlz4",
                                 "lz4 package not installed — run: pip install lz4"))
                except Exception as e:
                    res.append(("sessionstore.jsonlz4 | Error", str(e)))

        if not res:
            res.append(("Tor State", "No Tor Browser data found"))

        self.last_results, self.last_headers = res, ["Forensic Artifact", "Value"]
        AnalysisWindow("Tor Browser — Tor State & Network Artifacts", self.last_headers, res)

    def export_evidence(self):
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

def _run_splash(app):
    """Ghidra-style logo splash: fades in then out before main window shows."""
    raw = _open_logo(240)
    if raw is None:
        app.wm_attributes("-alpha", 1.0)
        app.lift()
        return
    try:
        tk_img = _PilImageTk.PhotoImage(raw)
    except Exception:
        app.wm_attributes("-alpha", 1.0)
        app.lift()
        return

    w, h = 320, 360
    splash = _tk.Toplevel(app)
    splash.overrideredirect(True)
    splash.configure(bg="#0d0d0d")
    splash.attributes("-alpha", 0.0)
    splash.attributes("-topmost", True)
    sw, sh = app.winfo_screenwidth(), app.winfo_screenheight()
    splash.geometry(f"{w}x{h}+{(sw - w) // 2}+{(sh - h) // 2}")

    # Win11 rounded corners via DWM
    try:
        DWMWA_WINDOW_CORNER_PREFERENCE = 33
        DWMWCP_ROUND = 2
        ctypes.windll.dwmapi.DwmSetWindowAttribute(
            ctypes.windll.user32.GetParent(splash.winfo_id()),
            DWMWA_WINDOW_CORNER_PREFERENCE,
            ctypes.byref(ctypes.c_int(DWMWCP_ROUND)),
            ctypes.sizeof(ctypes.c_int),
        )
    except Exception:
        pass

    # Canvas guarantees pixel-perfect centering regardless of widget sizes
    canvas = _tk.Canvas(splash, width=w, height=h, bg="#0d0d0d",
                        highlightthickness=0, bd=0)
    canvas.pack(fill="both", expand=True)
    canvas._tk_img = tk_img  # keep reference to prevent GC

    img_cy = h // 2 - 30          # center of the logo image
    canvas.create_image(w // 2, img_cy, image=tk_img, anchor="center")
    canvas.create_text(w // 2, img_cy + 142,
                       text="BrowsAR",
                       font=("Segoe UI", 20, "bold"), fill="#4f8ef7")
    canvas.create_text(w // 2, img_cy + 170,
                       text="Browser Forensic Suite",
                       font=("Segoe UI", 10), fill="#555555")
    splash.update()

    def _fade_in(a=0.0):
        if a < 1.0:
            splash.attributes("-alpha", round(min(a, 1.0), 2))
            splash.after(20, lambda: _fade_in(round(a + 0.05, 2)))
        else:
            splash.after(1400, _fade_out)

    def _fade_out(a=1.0):
        if a > 0.0:
            splash.attributes("-alpha", round(a, 2))
            splash.after(20, lambda: _fade_out(round(a - 0.05, 2)))
        else:
            splash.destroy()
            app.wm_attributes("-alpha", 1.0)
            app.lift()
            app.focus_force()

    _fade_in()


if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        app = BrowsAR_App()
        app.wm_attributes("-alpha", 0.0)  # invisible but not withdrawn - Toplevels still work
        _run_splash(app)
        app.mainloop()