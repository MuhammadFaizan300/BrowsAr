"""
tor_autofill.py — Tor Browser autofill / site-preference extractor.

Tor Browser disables formhistory.sqlite by default (signon.formlessPWHelper
and privacy.clearOnShutdown settings).  Instead this module reads:

  1. content-prefs.sqlite  — per-site user preferences (zoom, encoding, etc.)
                              Can contain .onion site entries.
  2. webappsstore.sqlite   — DOM localStorage / sessionStorage residue.
                              Sites can store arbitrary key-value data here.
"""

import os
import sqlite3
import shutil
import datetime
import re


def _prtime(t):
    if not t:
        return "N/A"
    try:
        return (datetime.datetime(1970, 1, 1) +
                datetime.timedelta(microseconds=int(t))).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "N/A"


def get_tor_autofill(profile_path):
    """
    Returns list of (source, key, value, extra) tuples from content-prefs and
    webappsstore databases.
    """
    results = []

    # --- 1. formhistory.sqlite (disabled by default but scan if present) ---
    fh_db = os.path.join(profile_path, "formhistory.sqlite")
    if os.path.exists(fh_db):
        tmp = "tor_fh_tmp.db"
        shutil.copyfile(fh_db, tmp)
        try:
            conn = sqlite3.connect(tmp)
            cur = conn.cursor()
            cur.execute("SELECT fieldname, value, timesUsed, firstUsed, lastUsed "
                        "FROM moz_formhistory ORDER BY lastUsed DESC")
            for field, value, times, first, last in cur.fetchall():
                results.append(("formhistory", field or "", value or "",
                                 f"Used {times}x | first:{_prtime(first)} last:{_prtime(last)}"))
            conn.close()
        except Exception as e:
            results.append(("formhistory | Error", str(e), "", ""))
        finally:
            try:
                os.remove(tmp)
            except OSError:
                pass
    else:
        results.append(("formhistory.sqlite",
                        "Not present — form history disabled by default in Tor Browser",
                        "", ""))

    # --- 2. content-prefs.sqlite (per-site preferences) ---
    cp_db = os.path.join(profile_path, "content-prefs.sqlite")
    if os.path.exists(cp_db):
        tmp2 = "tor_cp_tmp.db"
        shutil.copyfile(cp_db, tmp2)
        try:
            conn = sqlite3.connect(tmp2)
            cur = conn.cursor()
            cur.execute("""
                SELECT g.name, s.name, CAST(p.value AS TEXT)
                FROM prefs p
                JOIN groups g ON p.groupID = g.id
                JOIN settings s ON p.settingID = s.id
                ORDER BY g.name
            """)
            for site, setting, value in cur.fetchall():
                results.append(("content-prefs | Site", site or "global",
                                 setting or "", value or ""))
            conn.close()
        except Exception as e:
            results.append(("content-prefs | Error", str(e), "", ""))
        finally:
            try:
                os.remove(tmp2)
            except OSError:
                pass
    else:
        results.append(("content-prefs.sqlite", "Not found", "", ""))

    # --- 3. webappsstore.sqlite (DOM localStorage) ---
    wa_db = os.path.join(profile_path, "webappsstore.sqlite")
    if os.path.exists(wa_db):
        tmp3 = "tor_wa_tmp.db"
        shutil.copyfile(wa_db, tmp3)
        try:
            conn = sqlite3.connect(tmp3)
            cur = conn.cursor()
            # webappsstore2 is the main table
            cur.execute("SELECT scope, key, value FROM webappsstore2 ORDER BY scope")
            count = 0
            for scope, key, value in cur.fetchall():
                val_str = str(value or "")
                results.append(("localStorage | Scope", scope or "",
                                 key or "", val_str[:80] + ("..." if len(val_str) > 80 else "")))
                count += 1
            conn.close()
            if count == 0:
                results.append(("webappsstore.sqlite", "Empty — no DOM storage data", "", ""))
        except Exception as e:
            results.append(("webappsstore | Error", str(e), "", ""))
        finally:
            try:
                os.remove(tmp3)
            except OSError:
                pass
    else:
        results.append(("webappsstore.sqlite", "Not found", "", ""))

    if not results:
        results.append(("Info", "No autofill / site-preference data found", "", ""))
    return results
