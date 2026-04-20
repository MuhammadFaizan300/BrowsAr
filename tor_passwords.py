"""
tor_passwords.py — Tor Browser credential extractor (NSS / Mozilla PKCS#11).

Tor Browser disables password saving by default (signon.rememberSignons=false
in prefs.js).  This module attempts decryption anyway for cases where a user
has manually re-enabled the feature.  Decryption uses Mozilla's NSS library
(nss3.dll) via ctypes — no external Python packages required.

Requires:
  - Tor Browser to be CLOSED (NSS locks the profile directory while running).
  - Admin privileges are NOT needed — only read access to the profile.
"""

import os
import json
import base64
import ctypes
import shutil


# ---------------------------------------------------------------------------
# NSS / SECItem structures
# ---------------------------------------------------------------------------

class SECItem(ctypes.Structure):
    """Mozilla SECItem: a (type, data*, len) tuple used across NSS."""
    _fields_ = [
        ('type', ctypes.c_uint),
        ('data', ctypes.c_void_p),
        ('len',  ctypes.c_uint),
    ]


def _load_nss(browser_dir):
    """Load nss3.dll from the Tor Browser Browser/ directory."""
    # Load mozglue.dll first — it must be initialised before nss3
    for dep in ('mozglue.dll', 'msvcp140.dll', 'vcruntime140.dll'):
        dep_path = os.path.join(browser_dir, dep)
        if os.path.exists(dep_path):
            try:
                ctypes.CDLL(dep_path)
            except OSError:
                pass

    # Extend DLL search path (Python 3.8+ on Windows)
    try:
        os.add_dll_directory(browser_dir)
    except AttributeError:
        os.environ['PATH'] = browser_dir + os.pathsep + os.environ.get('PATH', '')

    nss_path = os.path.join(browser_dir, 'nss3.dll')
    if not os.path.exists(nss_path):
        return None, f"nss3.dll not found in {browser_dir}"

    try:
        nss3 = ctypes.CDLL(nss_path)
    except OSError as e:
        return None, f"Failed to load nss3.dll: {e}"

    # Set up function signatures
    nss3.NSS_Init.restype             = ctypes.c_int
    nss3.NSS_Init.argtypes            = [ctypes.c_char_p]
    nss3.NSS_Shutdown.restype         = ctypes.c_int
    nss3.NSS_Shutdown.argtypes        = []
    nss3.PK11_GetInternalKeySlot.restype  = ctypes.c_void_p
    nss3.PK11_GetInternalKeySlot.argtypes = []
    nss3.PK11_CheckUserPassword.restype   = ctypes.c_int
    nss3.PK11_CheckUserPassword.argtypes  = [ctypes.c_void_p, ctypes.c_char_p]
    nss3.PK11SDR_Decrypt.restype      = ctypes.c_int
    nss3.PK11SDR_Decrypt.argtypes     = [
        ctypes.POINTER(SECItem), ctypes.POINTER(SECItem), ctypes.c_void_p
    ]

    return nss3, None


def _decrypt_nss(nss3, enc_b64):
    """Decrypt a base64-encoded NSS-protected string."""
    try:
        decoded = base64.b64decode(enc_b64)
        buf      = ctypes.create_string_buffer(decoded)
        in_item  = SECItem(0, ctypes.cast(buf, ctypes.c_void_p), len(decoded))
        out_item = SECItem()
        rc = nss3.PK11SDR_Decrypt(ctypes.byref(in_item),
                                   ctypes.byref(out_item), None)
        if rc == 0 and out_item.data:
            return ctypes.string_at(out_item.data, out_item.len).decode('utf-8', errors='replace')
        return '[Decryption Failed]'
    except Exception as e:
        return f'[Error: {e}]'


def get_tor_passwords(profile_path, browser_root):
    """
    Returns list of (url, username, password) tuples.

    Parameters
    ----------
    profile_path : str
        Path to the profile.default directory.
    browser_root : str
        Root of the Tor Browser installation (contains Browser/ subdirectory).
    """
    logins_file = os.path.join(profile_path, 'logins.json')
    if not os.path.exists(logins_file):
        return [("Info",
                 "logins.json absent — Tor Browser disables password saving by default "
                 "(signon.rememberSignons=false in prefs.js)",
                 "")]

    browser_dir = os.path.join(browser_root, 'Browser')
    nss3, err = _load_nss(browser_dir)
    if err:
        return [("Error", err, "")]

    profile_enc = profile_path.encode('utf-8')
    if nss3.NSS_Init(profile_enc) != 0:
        return [("Error",
                 "NSS_Init failed — close Tor Browser first, then run the analysis.",
                 "")]

    results = []
    try:
        slot = nss3.PK11_GetInternalKeySlot()
        nss3.PK11_CheckUserPassword(slot, b'')   # empty master password (default)

        with open(logins_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        logins = data.get('logins', [])
        if not logins:
            results.append(("Info",
                             "logins.json is empty — no credentials stored",
                             ""))
        else:
            for login in logins:
                url      = login.get('hostname', 'N/A')
                username = _decrypt_nss(nss3, login.get('encryptedUsername', ''))
                password = _decrypt_nss(nss3, login.get('encryptedPassword', ''))
                results.append((url, username, password))
    except Exception as e:
        results.append(("Error", str(e), ""))
    finally:
        try:
            nss3.NSS_Shutdown()
        except Exception:
            pass

    return results or [("Info", "No passwords found", "")]
