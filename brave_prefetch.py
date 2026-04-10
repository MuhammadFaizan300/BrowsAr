import os
import sys
import ctypes
import struct
import datetime

# --- OS CONSTANTS ---
PREFETCH_PATH = r"C:\Windows\Prefetch"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def convert_filetime(ft):
    """Converts 64-bit Windows FILETIME to readable format."""
    try:
        us = ft / 10.
        return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=us)).strftime('%Y-%m-%d %H:%M:%S')
    except:
        return "N/A"

def analyze_prefetch():
    print("--- Brows-AR: Prefetch Execution Analysis ---")
    
    if not os.path.exists(PREFETCH_PATH):
        print("[-] Prefetching is disabled on this system.")
        return

    found = False
    try:
        for filename in os.listdir(PREFETCH_PATH):
            if filename.startswith("BRAVE.EXE") and filename.endswith(".pf"):
                found = True
                path = os.path.join(PREFETCH_PATH, filename)
                
                # Get OS-level timestamps (Forensic Fallback)
                stat = os.stat(path)
                birth_time = datetime.datetime.fromtimestamp(stat.st_ctime)
                last_mod = datetime.datetime.fromtimestamp(stat.st_mtime)

                with open(path, "rb") as f:
                    data = f.read()
                    
                    # Check for MAM (Compressed) vs SCCA (Uncompressed)
                    if data[0:3] == b'MAM':
                        print(f"\n[!] Artifact: {filename} (Compressed - MAM)")
                        print(f"    [*] Note: Windows 10/11 compresses Prefetch. Using FileStats.")
                        print(f"    Estimated First Run: {birth_time}")
                        print(f"    Estimated Last Run:  {last_mod}")
                    else:
                        # Parse standard SCCA header (Older systems or manually decompressed)
                        try:
                            # Run count is usually at 0xD0 (Win10) or 0x90 (Win7)
                            run_count = struct.unpack("<I", data[0xD0:0xD0+4])[0]
                            last_run_64 = struct.unpack("<Q", data[0x80:0x80+8])[0]
                            print(f"\n[+] Artifact: {filename}")
                            print(f"    Total Run Count: {run_count}")
                            print(f"    Last Execution:  {convert_filetime(last_run_64)}")
                        except:
                            print(f"\n[-] Partial Parse for {filename}: Check headers manually in Hex.")

    except PermissionError:
        print("[-] Error: Permission Denied. Elevation failed.")
    except Exception as e:
        print(f"[-] Error: {e}")

    if not found:
        print("[-] No Brave Prefetch files found. Ensure Brave has been launched at least once.")

def main():
    # 1. Trigger UAC Elevation
    if not is_admin():
        print("[*] Requesting Administrative Privileges for System Folder Access...")
        # Relaunch the script as admin
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        return

    # 2. Run Analysis
    analyze_prefetch()
    input("\n[*] Analysis Complete. Press Enter to exit...")

if __name__ == "__main__":
    main()