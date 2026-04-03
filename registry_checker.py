import winreg

def get_brave_registry_info():
    print("--- Brave Browser Registry Analysis ---")
    
    # Path where Brave stores its installation/version info
    path = r"Software\BraveSoftware\Brave-Browser\BLBeacon"
    
    try:
        # Open the Registry Key (HKEY_CURRENT_USER is safer for your first test)
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ)
        
        # Pull the version and installation date
        version, _ = winreg.QueryValueEx(key, "version")
        print(f"[+] Brave Version Found: {version}")
        
        # Pro Tip: 'BLBeacon' is often used to track 'last seen' or 'installation' details
        print("[+] Registry Key successfully accessed. Installation verified.")
        
        winreg.CloseKey(key)
    except FileNotFoundError:
        print("[-] Brave Registry keys not found. It might be a 'portable' version or not installed for this user.")
    except Exception as e:
        print(f"[-] Error accessing Registry: {e}")

if __name__ == "__main__":
    get_brave_registry_info()