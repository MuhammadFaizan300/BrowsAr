import os
import sqlite3
import shutil
from datetime import datetime, timedelta

def get_brave_history():
    # 1. Locate the path dynamically
    local_app_data = os.getenv('LOCALAPPDATA')
    history_path = os.path.join(local_app_data, r'BraveSoftware\Brave-Browser\User Data\Default\History')
    
    # 2. Forensic Integrity: Create a copy to analyze (don't touch the original!)
    temp_history = "temp_brave_history.db"
    try:
        shutil.copy2(history_path, temp_history)
        print(f"[+] Forensic copy created: {temp_history}")
    except FileNotFoundError:
        print("[-] Error: Brave History file not found. Is Brave installed?")
        return

    # 3. Connect and Query the SQLite Database
    try:
        conn = sqlite3.connect(temp_history)
        cursor = conn.cursor()
        
        # This query gets the URL and the 'last_visit_time'
        # Brave uses 'WebKit' time: microseconds since Jan 1, 1601
        cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 10")
        
        print(f"\n{'DATE & TIME':<20} | {'URL'}")
        print("-" * 80)
        
        for url, title, visit_time in cursor.fetchall():
            # Convert WebKit timestamp to readable format
            readable_time = datetime(1601, 1, 1) + timedelta(microseconds=visit_time)
            print(f"{str(readable_time)[:19]:<20} | {url}")
            
        conn.close()
    except Exception as e:
        print(f"[-] Error reading database: {e}")
    finally:
        # Clean up the temporary copy if you wish, or keep it for the Hex Viewer
        # os.remove(temp_history)
        pass

if __name__ == "__main__":
    get_brave_history()