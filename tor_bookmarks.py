"""
tor_bookmarks.py — Tor Browser bookmark extractor.

Bookmarks live in places.sqlite (moz_bookmarks joined with moz_places).
Tor Browser ships with a default set of bookmarks; any user-added ones are
forensically significant.
"""

import os
import sqlite3
import shutil
import datetime


def _prtime(t):
    if not t:
        return "N/A"
    try:
        return (datetime.datetime(1970, 1, 1) +
                datetime.timedelta(microseconds=int(t))).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "N/A"


def get_tor_bookmarks(profile_path):
    """
    Returns list of (title, url, date_added, last_modified) tuples.
    """
    db = os.path.join(profile_path, "places.sqlite")
    if not os.path.exists(db):
        return [("Info", "places.sqlite not found", "", "")]

    tmp = "tor_bm_tmp.db"
    shutil.copyfile(db, tmp)
    results = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("""
            SELECT b.title, p.url, b.dateAdded, b.lastModified
            FROM moz_bookmarks b
            JOIN moz_places p ON b.fk = p.id
            WHERE b.type = 1
            ORDER BY b.dateAdded DESC
        """)
        for title, url, added, modified in cur.fetchall():
            results.append((title or "(no title)", url or "",
                             _prtime(added), _prtime(modified)))
        conn.close()
    except Exception as e:
        results.append(("Error", str(e), "", ""))
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    if not results:
        results.append(("Info", "No bookmarks found", "", ""))
    return results
