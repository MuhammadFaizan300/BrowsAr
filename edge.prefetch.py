import os
import struct
import datetime

def analyze():
    PREFETCH_PATH = r"C:\Windows\Prefetch"
    EXE_PREFIX = "MSEDGE.EXE"
    results = []
    
    if not os.path.exists(PREFETCH_PATH): return [("Status", "Disabled")]

    for filename in os.listdir(PREFETCH_PATH):
        if filename.startswith(EXE_PREFIX) and filename.endswith(".pf"):
            path = os.path.join(PREFETCH_PATH, filename)
            stat = os.stat(path)
            
            with open(path, "rb") as f:
                data = f.read(8) # Check header
                if data[0:3] == b'MAM':
                    results.append((filename, f"Compressed (MAM) | Last Run: {datetime.datetime.fromtimestamp(stat.st_mtime)}"))
                else:
                    # Basic SCCA Parsing logic from your Brave script
                    try:
                        f.seek(0xD0)
                        run_count = struct.unpack("<I", f.read(4))[0]
                        results.append((filename, f"SCCA | Run Count: {run_count}"))
                    except:
                        results.append((filename, "SCCA | Manual Hex Review Required"))
    return results