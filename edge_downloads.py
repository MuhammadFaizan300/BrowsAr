import os
import sqlite3
import shutil
import datetime

def convert_time(dw_time):
    if dw_time == 0: return "N/A"
    return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=dw_time)).strftime('%Y-%m-%d %H:%M:%S')

def get_downloads():
    path = os.path.join(os.environ['LOCALAPPDATA'], r"Microsoft\Edge\User Data\Default\History")
    if not os.path.exists(path): return "[-] Edge History file not found."
    
    temp_db = "edge_dw_tmp"
    shutil.copyfile(path, temp_db)
    
    results = []
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        cursor.execute("SELECT target_path, start_time, received_bytes, state, tab_url FROM downloads")
        for row in cursor.fetchall():
            results.append((row[0], convert_time(row[1]), f"{row[2]/1024:.2f} KB", row[3], row[4]))
        conn.close()
    finally:
        if os.path.exists(temp_db): os.remove(temp_db)
    return results

if __name__ == "__main__":
    for d in get_downloads(): print(d)