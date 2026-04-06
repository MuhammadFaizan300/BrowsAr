import os

def browsar_full_hex_viewer(file_path, sector_size=512):
    """
    Displays the entire raw content of a file.
    Left: Hexadecimal | Right: ASCII Translation
    """
    if not os.path.exists(file_path):
        print(f"[-] Error: File not found at {file_path}")
        return

    file_size = os.path.getsize(file_path)
    print(f"--- Brows-AR Low-Level Analysis ---")
    print(f"[FILE]: {os.path.basename(file_path)}")
    print(f"[SIZE]: {file_size} bytes")
    print(f"{'-' * 75}")
    print(f"{'Offset':<10} {'Hex Content':<48} {'ASCII'}")
    print(f"{'-' * 75}")

    try:
        with open(file_path, 'rb') as f:
            offset = 0
            while True:
                # Read 16 bytes at a time for a standard view
                chunk = f.read(16)
                if not chunk:
                    break
                
                # 1. Convert to Hex (e.g., '61 62 63')
                hex_content = ' '.join(f"{b:02x}" for b in chunk)
                
                # 2. Convert to ASCII (replace non-printable bytes with '.')
                # 32 to 126 are the standard readable characters
                ascii_content = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
                
                # 3. Print the formatted line
                # Format: [8-digit Offset] [16 bytes of Hex] |[16 chars of ASCII]|
                print(f"{offset:08x}  {hex_content:<48}  |{ascii_content}|")
                
                offset += 16
                
                # Safety break for terminal testing (remove this for the final UI version)
                if offset >= 4096:
                    print(f"\n[!] Paused at 4KB (1 NTFS Cluster). Full file is {file_size} bytes.")
                    break
                    
    except Exception as e:
        print(f"[-] Forensic Error: {e}")

if __name__ == "__main__":
    # Point this directly to the Brave History file
    # On most systems: AppData\Local\BraveSoftware\Brave-Browser\User Data\Default\History
    history_file = os.path.join(os.environ['LOCALAPPDATA'], 
                                r"BraveSoftware\Brave-Browser\User Data\Default\History")
    
    browsar_full_hex_viewer(history_file)