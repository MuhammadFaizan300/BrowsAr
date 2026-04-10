import os
import sqlite3
import shutil
import datetime

def convert_time(dw_time):
    """Converts Chromium timestamp (microseconds since 1601) to readable format."""
    if dw_time == 0: return "N/A"
    return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=dw_time)).strftime('%Y-%m-%d %H:%M:%S')

def get_downloads():
    path = os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data\Default\History")
    if not os.path.exists(path): return "[-] Brave History file not found."
    
    temp_db = "brave_dw_tmp"
    shutil.copyfile(path, temp_db)
    
    results = []
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        # Querying the 'downloads' and 'downloads_url_chains' tables
        query = """
            SELECT target_path, start_time, received_bytes, state, tab_url 
            FROM downloads
        """
        cursor.execute(query)
        for row in cursor.fetchall():
            file_path = row[0]
            time_str = convert_time(row[1])
            size = f"{row[2] / 1024:.2f} KB"
            status = "Complete" if row[3] == 1 else ("Cancelled" if row[3] == 2 else "Interrupted")
            url = row[4]
            results.append((file_path, time_str, size, status, url))
        conn.close()
    finally:
        if os.path.exists(temp_db): os.remove(temp_db)
    
    return results

if __name__ == "__main__":
    data = get_downloads()
    print(f"--- Brave Download History ({len(data)} artifacts) ---")
    for d in data:
        print(f"\n[FILE]: {d[0]}\n[TIME]: {d[1]}\n[SIZE]: {d[2]}\n[STAT]: {d[3]}\n[suspicious link removed]: {d[4]}")