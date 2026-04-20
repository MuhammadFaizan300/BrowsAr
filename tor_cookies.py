"""
tor_cookies.py — Tor Browser cookie extractor.

Tor Browser stores cookies in cookies.sqlite (moz_cookies table) during a
session.  Cookies are deleted on clean exit by default.  If the browser was
force-killed, cookies from .onion sites will survive here.
"""

import os
import sqlite3
import shutil
import datetime


_SAMESITE = {0: "None", 1: "Lax", 2: "Strict"}


def get_tor_cookies(profile_path):
    """
    Returns list of (host, name, value, path, last_accessed, flags) tuples.
    """
    db = os.path.join(profile_path, "cookies.sqlite")
    if not os.path.exists(db):
        return [("Info", "cookies.sqlite not found", "", "", "", "")]

    tmp = "tor_ck_tmp.db"
    shutil.copyfile(db, tmp)
    results = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("""
            SELECT host, name, value, path, expiry,
                   isSecure, isHttpOnly, sameSite, lastAccessed
            FROM moz_cookies
            ORDER BY lastAccessed DESC
        """)
        for host, name, value, path, expiry, secure, httponly, samesite, last in cur.fetchall():
            flags = []
            if secure:
                flags.append("Secure")
            if httponly:
                flags.append("HttpOnly")
            flags.append(f"SameSite={_SAMESITE.get(samesite, str(samesite))}")

            try:
                exp_str = (datetime.datetime.fromtimestamp(expiry).strftime('%Y-%m-%d %H:%M:%S')
                           if expiry > 0 else "Session")
            except Exception:
                exp_str = str(expiry)

            try:
                la_str = (datetime.datetime(1970, 1, 1) +
                          datetime.timedelta(microseconds=int(last))).strftime('%Y-%m-%d %H:%M:%S')
            except Exception:
                la_str = "N/A"

            val = (value or "")
            display_val = val[:60] + ("..." if len(val) > 60 else "")
            results.append((host or "", name or "", display_val,
                             path or "", la_str, ", ".join(flags)))
        conn.close()
    except Exception as e:
        results.append(("Error", str(e), "", "", "", ""))
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    if not results:
        results.append(("Info",
                        "No cookies found — Tor Browser deletes all cookies on clean exit",
                        "", "", "", ""))
    return results
