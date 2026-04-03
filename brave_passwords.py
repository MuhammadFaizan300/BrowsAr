import os
import json
import sqlite3
import shutil
import base64
import win32crypt # Part of pywin32
from Cryptodome.Cipher import AES # Part of pycryptodomex

def get_master_key():
    local_state_path = os.path.join(os.environ['USERPROFILE'], 
        r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    
    # Extract the key and decode from Base64
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # Remove DPAPI prefix 'DPAPI' (5 bytes) and decrypt
    return win32crypt.CryptUnprotectData(encrypted_key[5:], None, None, None, 0)[1]

def decrypt_password(buff, master_key):
    try:
        # Modern Brave passwords start with 'v10' or 'v11' (3 bytes)
        # The next 12 bytes are the IV (Initialization Vector)
        iv = buff[3:15] 
        payload = buff[15:]
        
        # In newer versions, the last 16 bytes of the payload are the 'Auth Tag'
        ciphertext = payload[:-16]
        tag = payload[-16:]
        
        cipher = AES.new(master_key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt_and_verify(ciphertext, tag)
        return decrypted_pass.decode()
    except Exception as e:
        return f"Decryption Failed: {str(e)}"

def extract_brave_passwords():
    db_path = os.path.join(os.environ['USERPROFILE'], 
        r"AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\Login Data")
    shutil.copy2(db_path, "temp_login_data.db") # Forensic copy [cite: 73]
    
    master_key = get_master_key()
    conn = sqlite3.connect("temp_login_data.db")
    cursor = conn.cursor()
    cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
    
    print(f"\n{'SITE':<40} | {'USERNAME':<20} | {'PASSWORD'}")
    print("-" * 80)
    
    # Replace your loop with this to see the "Signature" of the encryption
    for url, user, enc_pass in cursor.fetchall():
        if user:
            # Check the first 3 bytes to see the version (v10, v11, v20?)
            version_tag = enc_pass[:3].decode(errors='ignore')
            print(f"Site: {url} | Version Tag: {version_tag} | Blob Length: {len(enc_pass)}")
        
            password = decrypt_password(enc_pass, master_key)
            print(f"Result: {password}\n")

if __name__ == "__main__":
    extract_brave_passwords()