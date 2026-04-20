"""
tor_registry.py — Windows Registry artifact scanner for Tor Browser.

Tor Browser (portable) deliberately creates almost no registry footprint.
However Windows itself records execution traces in:

  1. UserAssist    — ROT-13 encoded run history (HKCU Explorer)
  2. MuiCache      — friendly names of recently launched executables
  3. AppCompatFlags / ShimCache — (read via browsar_main, not here)
  4. Uninstall keys— present only if installed via the NSIS installer
  5. Run keys      — persistence; rare but forensically high-value if found
"""

import winreg
import struct
import datetime


def _rot13(text):
    result = []
    for ch in text:
        if 'a' <= ch <= 'z':
            result.append(chr((ord(ch) - ord('a') + 13) % 26 + ord('a')))
        elif 'A' <= ch <= 'Z':
            result.append(chr((ord(ch) - ord('A') + 13) % 26 + ord('A')))
        else:
            result.append(ch)
    return ''.join(result)


def _wintime(t):
    try:
        return (datetime.datetime(1601, 1, 1) +
                datetime.timedelta(microseconds=t // 10)).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "N/A"


def _run_count(data):
    try:
        return struct.unpack('<I', data[4:8])[0]
    except Exception:
        return "?"


def get_tor_registry():
    """
    Returns list of (artifact_label, value) tuples for Tor Browser registry
    artifacts found on this system.
    """
    results = []

    # ------------------------------------------------------------------ #
    # 1. UserAssist — ROT-13 decoded run history                         #
    # ------------------------------------------------------------------ #
    ua_guids = [
        '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}',   # programs
        '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}',   # shortcuts
    ]
    for guid in ua_guids:
        try:
            path = (rf"Software\Microsoft\Windows\CurrentVersion\Explorer"
                    rf"\UserAssist\{guid}\Count")
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    n, d, _ = winreg.EnumValue(key, i)
                    decoded = _rot13(n)
                    if any(kw in decoded.lower() for kw in ('tor', 'firefox')):
                        runs = _run_count(d) if len(d) >= 8 else '?'
                        results.append(("UserAssist | Decoded Path",
                                         f"{decoded}  (Runs: {runs})"))
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    # 2. MuiCache — recently executed executables with friendly names    #
    # ------------------------------------------------------------------ #
    try:
        mui_path = (r"Software\Classes\Local Settings\Software\Microsoft"
                    r"\Windows\Shell\MuiCache")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, mui_path) as key:
            count = winreg.QueryInfoKey(key)[1]
            for i in range(count):
                n, v, _ = winreg.EnumValue(key, i)
                if any(kw in n.lower() for kw in ('tor', 'firefox')) and '.exe' in n.lower():
                    results.append(("MuiCache | Executable Path", n))
                    results.append(("MuiCache | Friendly Name", str(v)))
    except OSError:
        pass

    # ------------------------------------------------------------------ #
    # 3. Uninstall keys (NSIS installer variant)                         #
    # ------------------------------------------------------------------ #
    uninstall_roots = [
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    _interesting = ("DisplayName", "DisplayVersion", "InstallLocation",
                    "InstallDate", "Publisher", "UninstallString")
    for root, base_path in uninstall_roots:
        try:
            with winreg.OpenKey(root, base_path) as base:
                sub_count = winreg.QueryInfoKey(base)[0]
                for i in range(sub_count):
                    sub_name = winreg.EnumKey(base, i)
                    if 'tor' not in sub_name.lower():
                        continue
                    full_path = rf"{base_path}\{sub_name}"
                    try:
                        with winreg.OpenKey(root, full_path) as sk:
                            vcount = winreg.QueryInfoKey(sk)[1]
                            for j in range(vcount):
                                vn, vd, _ = winreg.EnumValue(sk, j)
                                if vn in _interesting:
                                    results.append((f"Uninstall [{sub_name}] | {vn}",
                                                     str(vd)))
                    except OSError:
                        pass
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    # 4. Run / RunOnce persistence keys                                  #
    # ------------------------------------------------------------------ #
    run_paths = [
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_CURRENT_USER,
         r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]
    for root, path in run_paths:
        try:
            with winreg.OpenKey(root, path) as key:
                for i in range(winreg.QueryInfoKey(key)[1]):
                    n, v, _ = winreg.EnumValue(key, i)
                    if any(kw in str(v).lower() for kw in ('tor', 'firefox')):
                        results.append(("Run Key | AUTOSTART", f"{n}: {v}"))
        except OSError:
            pass

    # ------------------------------------------------------------------ #
    # 5. AppX / Shell Open / Protocol handlers (optional breadcrumbs)   #
    # ------------------------------------------------------------------ #
    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, r"TorBrowserHTML") as key:
            results.append(("Protocol Handler", "TorBrowserHTML registered in HKCR"))
    except OSError:
        pass

    if not results:
        results.append(("Registry Scan",
                        "No Tor Browser registry artifacts found on this system "
                        "(expected for portable install — Windows leaves fewer traces)"))
    return results
