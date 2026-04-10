import os
import sys
import ctypes
import customtkinter as ctk
from tkinter import messagebox

# --- 1. ADMIN ELEVATION LOGIC ---
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# --- 2. BROWSER DISCOVERY ENGINE ---
class BrowserScanner:
    @staticmethod
    def hunt_for_tor():
        """Forensic hunt for Tor on Desktop, Downloads, and AppData (Depth: 7)"""
        user_profile = os.environ['USERPROFILE']
        hunt_spots = [
            os.path.join(user_profile, 'Desktop'),
            os.path.join(user_profile, 'Downloads'),
            os.environ['LOCALAPPDATA'],
        ]
        
        for base in hunt_spots:
            if not os.path.exists(base): continue
            for root, dirs, files in os.walk(base):
                # Signature: firefox.exe inside a Tor Browser folder
                if "firefox.exe" in files and "Tor Browser" in root:
                    # Path to the actual profile data
                    data_path = os.path.join(root, "TorBrowser", "Data", "Browser")
                    if os.path.exists(data_path):
                        return data_path
                
                # Depth limit to prevent UI hanging
                if root.count(os.sep) - base.count(os.sep) > 7:
                    del dirs[:] 
        return None

    @staticmethod
    def get_installed_browsers():
        """Gathers paths for all supported browsers."""
        standard_paths = {
            "Brave": os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data"),
            "Chrome": os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data"),
            "Edge": os.path.join(os.environ['LOCALAPPDATA'], r"Microsoft\Edge\User Data"),
            "Firefox": os.path.join(os.environ['APPDATA'], r"Mozilla\Firefox\Profiles"),
        }
        
        detected = []
        for name, path in standard_paths.items():
            if os.path.exists(path):
                detected.append((name, path))
        
        # Hunt for the Tor "Ghost"
        tor_path = BrowserScanner.hunt_for_tor()
        if tor_path:
            detected.append(("Tor", tor_path))
            
        return detected

# --- 3. MAIN DASHBOARD UI ---
class BrowsAR_App(ctk.CTk):
    def __init__(self):
        super().__init__()

        # Window Setup
        self.title("Brows-AR | Advanced Browser Forensics Station")
        self.geometry("1200x800")
        ctk.set_appearance_mode("dark")
        
        # Sidebar for Navigation
        self.sidebar = ctk.CTkFrame(self, width=220, corner_radius=0)
        self.sidebar.pack(side="left", fill="y")
        
        self.logo_label = ctk.CTkLabel(self.sidebar, text="Brows-AR", font=ctk.CTkFont(size=24, weight="bold"))
        self.logo_label.pack(padx=20, pady=30)

        self.label = ctk.CTkLabel(self.sidebar, text="EVIDENCE SOURCES", font=ctk.CTkFont(size=12, weight="bold"))
        self.label.pack(pady=(10, 5))

        # Dynamically build sidebar buttons
        self.detected_browsers = BrowserScanner.get_installed_browsers()
        for name, path in self.detected_browsers:
            btn = ctk.CTkButton(
                self.sidebar, 
                text=f"Investigate {name}", 
                command=lambda n=name, p=path: self.load_browser_cockpit(n, p)
            )
            btn.pack(pady=8, padx=15)

        # Main Investigation Workspace
        self.main_view = ctk.CTkFrame(self, corner_radius=15, fg_color="#1e1e1e")
        self.main_view.pack(side="right", fill="both", expand=True, padx=20, pady=20)

        self.welcome_text = ctk.CTkLabel(
            self.main_view, 
            text="[*] SYSTEM TRIAGE COMPLETE\n\nPlease select a browser from the sidebar to begin analysis.",
            font=("Consolas", 16)
        )
        self.welcome_text.place(relx=0.5, rely=0.5, anchor="center")

    def load_browser_cockpit(self, browser_name, browser_path):
        """Initializes the multi-tab cockpit for the selected browser."""
        # Clear the workspace
        for widget in self.main_view.winfo_children():
            widget.destroy()
        
        # Forensic Header
        title_text = f"ANALYZING: {browser_name.upper()} | PATH: {browser_path}"
        header = ctk.CTkLabel(self.main_view, text=title_text, font=("Consolas", 14, "bold"), text_color="#1f538d")
        header.pack(pady=15, padx=20, anchor="w")

        # Tabbed Forensic System
        self.tabview = ctk.CTkTabview(self.main_view, segmented_button_selected_color="#1f538d")
        self.tabview.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        self.tabview.add("Hex Explorer")
        self.tabview.add("Passwords")
        self.tabview.add("History")
        self.tabview.add("Registry")
        self.tabview.add("Prefetch")

        # PHASE 2 PREVIEW: Hex Explorer Textbox
        self.hex_display = ctk.CTkTextbox(self.tabview.tab("Hex Explorer"), font=("Consolas", 13), wrap="none")
        self.hex_display.pack(fill="both", expand=True, padx=10, pady=10)
        
        init_msg = f"[*] Ready to stream binary data for {browser_name}...\n[*] Offset: 00000000\n[*] Mode: Read-Only (Forensic Integrity)"
        self.hex_display.insert("0.0", init_msg)

# --- 4. EXECUTION ---
if __name__ == "__main__":
    if not is_admin():
        # Relaunch as admin to access system folders (Prefetch/Registry)
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        app = BrowsAR_App()
        app.mainloop()