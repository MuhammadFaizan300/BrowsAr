import os
import sys
import ctypes
import json
import winreg
import datetime
import struct
import shutil

# --- 1. ADMIN AUTO-ELEVATION ---
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def run_as_admin():
    if not is_admin():
        print("[*] Requesting Administrator Privileges...")
        # Re-run the script with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        sys.exit()

def rot13(text):
    result = ""
    for char in text:
        if 'a' <= char <= 'z': result += chr((ord(char) - ord('a') + 13) % 26 + ord('a'))
        elif 'A' <= char <= 'Z': result += chr((ord(char) - ord('A') + 13) % 26 + ord('A'))
        else: result += char
    return result

def get_brave_paths():
    base = os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data")
    # Checking for 'Default' profile
    profile = os.path.join(base, "Default")
    return base, profile

def get_prefetch_history(file_path):
    """Extracts up to 8 last run times from a .pf file."""
    with open(file_path, 'rb') as f:
        f.seek(0x80) # Offset for run count in standard SCCA
        run_count = struct.unpack("<I", f.read(4))[0]
        
        # Windows 10/11 stores 8 timestamps starting at 0x80 or 0x98 
        # depending on version. We can loop through them.
        timestamps = []
        f.seek(0x80) # Adjust based on MAM/SCCA header
        # ... (complex parsing logic for all 8 timestamps)
def scan_tor_artifacts():
    user_data_path, profile_path = get_brave_paths()
    print("="*70)
    print(f"BRAVE TOR FORENSIC SCANNER | VERSION 3.0 (ADMIN ENHANCED)")
    print("="*70)

    # 1. Component Detection
    tor_folder = os.path.join(user_data_path, "cpoalefficncklhjfpglfiplenlpccdb")
    print(f"\n[1] Checking Brave-Tor Component Folder...")
    if os.path.exists(tor_folder):
        m_time = datetime.datetime.fromtimestamp(os.path.getmtime(tor_folder))
        print(f" [+] FOUND: Brave Tor Plugin exists.")
        print(f"     Last Updated/Initialized: {m_time}")
    else:
        print(" [-] Tor component folder not found in Brave's directory.")

    # 2. UserAssist Registry (Execution Logs)
    print(f"\n[2] Scanning UserAssist (Registry History)...")
    try:
        ua_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}\Count"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ua_path) as key:
            found_ua = False
            for i in range(winreg.QueryInfoKey(key)[1]):
                name, data, _ = winreg.EnumValue(key, i)
                decoded_name = rot13(name)
                # Filtering for Tor or Brave-Tor specifically
                if "tor" in decoded_name.lower():
                    found_ua = True
                    run_count = struct.unpack("<I", data[4:8])[0]
                    # Bytes 60-68 are the FILETIME for last execution
                    raw_time = struct.unpack("<Q", data[60:68])[0]
                    last_run = (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=raw_time/10)).strftime('%Y-%m-%d %H:%M:%S') if raw_time > 0 else "Never"
                    print(f" [+] FOUND EXE: {decoded_name}")
                    print(f"     Runs: {run_count} | Last Seen: {last_run}")
            if not found_ua: print(" [-] No specific Tor execution logs found.")
    except Exception as e: print(f" [!] Registry Access error: {e}")

    # 3. Preferences Leak (Fixed 'bool' error)
    print(f"\n[3] Searching Preferences for .onion Site Leaks...")
    prefs_file = os.path.join(profile_path, "Preferences")
    if os.path.exists(prefs_file):
        temp_prefs = "prefs_tor_tmp"
        try:
            shutil.copyfile(prefs_file, temp_prefs)
            with open(temp_prefs, "r", encoding="utf-8") as f:
                prefs = json.load(f)
                # Robust dictionary checking to prevent 'bool' errors
                content_settings = prefs.get("profile", {}).get("content_settings", {})
                exceptions = content_settings.get("exceptions", {})
                
                found_leaks = False
                if isinstance(exceptions, dict):
                    for setting_type, value in exceptions.items():
                        if isinstance(value, dict): # Check if the setting has a list of sites
                            for site in value:
                                if ".onion" in str(site):
                                    found_leaks = True
                                    print(f" [+] PERSISTENT ONION RECORD: {site}")
                                    print(f"     Setting Context: {setting_type}")
                
                if not found_leaks: print(" [-] No persistent .onion leaks found in Preferences.")
        except Exception as e: print(f" [!] Error parsing JSON: {e}")
        finally:
            if os.path.exists(temp_prefs): os.remove(temp_prefs)
    else: print(" [-] Preferences file not found.")

    # 4. Prefetch Artifacts (Requires Admin)
    print(f"\n[4] Scanning Windows Prefetch (Kernel Artifacts)...")
    pf_dir = r"C:\Windows\Prefetch"
    try:
        found_pf = False
        for f in os.listdir(pf_dir):
            if ("TOR" in f.upper() or "BRAVE" in f.upper()) and f.endswith(".pf"):
                path = os.path.join(pf_dir, f)
                m_time = datetime.datetime.fromtimestamp(os.path.getmtime(path))
                found_pf = True
                print(f" [+] FOUND ARTIFACT: {f:<30} | Last Run: {m_time}")
        if not found_pf: print(" [-] No Tor/Brave prefetch files found.")
    except PermissionError:
        print(" [!] PERMISSION DENIED: Prefetch requires Admin privileges.")

    print("\n" + "="*70)
    print("SCAN COMPLETE")
    print("="*70)

if __name__ == "__main__":
    run_as_admin() # Triggers the UAC popup
    scan_tor_artifacts()
    input("\nPress Enter to close...") # Keep window open to see results