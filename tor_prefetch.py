"""
tor_prefetch.py — Windows Prefetch extractor for Tor Browser executables.

Scans C:\\Windows\\Prefetch for artifacts left by:
  - TOR.EXE      (the embedded Tor daemon)
  - FIREFOX.EXE  (Tor Browser's Firefox-based UI process)

Prefetch files persist even after Tor Browser is uninstalled and prove that
these executables ran on this machine.
"""

import os
import struct
import datetime

PREFETCH_PATH = r"C:\Windows\Prefetch"
_TARGETS = ["TOR.EXE", "FIREFOX.EXE"]


def _filetime_to_str(ft):
    """Convert 64-bit Windows FILETIME to readable string."""
    try:
        us = ft / 10.0
        return (datetime.datetime(1601, 1, 1) +
                datetime.timedelta(microseconds=us)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "N/A"


def get_tor_prefetch():
    """
    Returns list of (artifact_label, value) tuples for each TOR.EXE /
    FIREFOX.EXE prefetch file found.
    """
    results = []

    if not os.path.exists(PREFETCH_PATH):
        return [("Prefetch", "C:\\Windows\\Prefetch does not exist — prefetching disabled")]

    for exe_name in _TARGETS:
        found = False
        try:
            for filename in sorted(os.listdir(PREFETCH_PATH)):
                if not (filename.upper().startswith(exe_name) and
                        filename.endswith(".pf")):
                    continue
                found = True
                pf_path = os.path.join(PREFETCH_PATH, filename)
                stat = os.stat(pf_path)

                results.append((f"{exe_name} | Artifact File", filename))
                results.append((f"{exe_name} | Artifact Created",
                                 datetime.datetime.fromtimestamp(
                                     stat.st_ctime).strftime('%Y-%m-%d %H:%M:%S')))
                results.append((f"{exe_name} | Artifact Modified",
                                 datetime.datetime.fromtimestamp(
                                     stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')))

                try:
                    with open(pf_path, "rb") as f:
                        data = f.read()

                    if data[0:3] == b'MAM':
                        # Windows 10/11 MAM-compressed — exact run count not
                        # accessible without decompression; use file timestamps.
                        results.append((f"{exe_name} | Format",
                                         "MAM Compressed (Win10/11) — using file timestamps"))
                    else:
                        # Standard SCCA header
                        sig = data[0:4] if data[0:4] == b'SCCA' else data[4:8]
                        if sig == b'SCCA':
                            try:
                                run_count = struct.unpack("<I", data[0xD0:0xD0 + 4])[0]
                                results.append((f"{exe_name} | Total Run Count",
                                                 str(run_count)))
                                for i in range(8):
                                    ts_raw = struct.unpack(
                                        "<Q", data[0x80 + i * 8: 0x88 + i * 8])[0]
                                    if ts_raw:
                                        results.append((f"{exe_name} | Exec Time {i + 1}",
                                                         _filetime_to_str(ts_raw)))
                            except Exception:
                                results.append((f"{exe_name} | Parse",
                                                 "Could not parse SCCA header"))
                except PermissionError:
                    results.append((f"{exe_name} | Error",
                                     "Permission denied reading prefetch file"))
                except Exception as e:
                    results.append((f"{exe_name} | Error", str(e)))

        except PermissionError:
            results.append((f"{exe_name}", "Permission denied listing Prefetch directory"))

        if not found:
            results.append((f"{exe_name} | Status",
                             "No prefetch file found — executable not run on this system "
                             "(or prefetch disabled)"))

    return results or [("Prefetch", "No Tor Browser prefetch artifacts found")]
