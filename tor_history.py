"""
tor_history.py — Tor Browser browsing history extractor.

Tor Browser (Firefox ESR-based) stores URLs in places.sqlite using the
moz_places table. Tor Browser clears history on exit by default, but if the
browser is force-killed or 'Never remember history' is turned off, records
will survive.
"""

import os
import sqlite3
import shutil
import datetime


def _prtime(t):
    """Convert Firefox PRTime (microseconds since 1970-01-01 UTC) to string."""
    if not t:
        return "N/A"
    try:
        return (datetime.datetime(1970, 1, 1) +
                datetime.timedelta(microseconds=int(t))).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "N/A"


def get_tor_history(profile_path):
    """
    Returns list of (url, title, visit_count, last_visit) tuples from
    the Tor Browser profile's places.sqlite.
    """
    db = os.path.join(profile_path, "places.sqlite")
    if not os.path.exists(db):
        return [("Info", "places.sqlite not found — Tor Browser may not have been used yet", "", "")]

    tmp = "tor_hist_tmp.db"
    shutil.copyfile(db, tmp)
    results = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("""
            SELECT url, title, visit_count, last_visit_date
            FROM moz_places
            WHERE visit_count > 0
            ORDER BY last_visit_date DESC
        """)
        for url, title, count, lvt in cur.fetchall():
            results.append((url or "", title or "", str(count or 0), _prtime(lvt)))
        conn.close()
    except Exception as e:
        results.append(("Error", str(e), "", ""))
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    if not results:
        results.append(("Info",
                        "No history found — Tor Browser clears history on clean exit by default",
                        "", ""))
    return results
