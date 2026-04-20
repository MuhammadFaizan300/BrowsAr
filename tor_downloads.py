"""
tor_downloads.py — Tor Browser download history extractor.

Firefox 26+ stores downloads as annotations in places.sqlite via the
moz_annos / moz_anno_attributes tables using the 'downloads/destinationFileURI'
and 'downloads/metaData' annotation names.
"""

import os
import sqlite3
import shutil
import datetime
import json


def _prtime(t):
    if not t:
        return "N/A"
    try:
        return (datetime.datetime(1970, 1, 1) +
                datetime.timedelta(microseconds=int(t))).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return "N/A"


_STATE_MAP = {1: "Completed", 2: "Downloading", 3: "Paused", 4: "Failed",
              5: "Canceled", 6: "Blocked (malware)", 7: "Dirty"}


def get_tor_downloads(profile_path):
    """
    Returns list of (source_url, local_path, time, size, status) tuples.
    """
    db = os.path.join(profile_path, "places.sqlite")
    if not os.path.exists(db):
        return [("Info", "places.sqlite not found", "", "", "")]

    tmp = "tor_dl_tmp.db"
    shutil.copyfile(db, tmp)
    results = []
    try:
        conn = sqlite3.connect(tmp)
        cur = conn.cursor()
        cur.execute("""
            SELECT p.url,
                   a_dest.content,
                   a_meta.content,
                   a_dest.lastModified
            FROM moz_places p
            INNER JOIN moz_annos a_dest ON p.id = a_dest.place_id
            INNER JOIN moz_anno_attributes aa_dest
                ON a_dest.anno_attribute_id = aa_dest.id
                AND aa_dest.name = 'downloads/destinationFileURI'
            LEFT JOIN moz_annos a_meta ON p.id = a_meta.place_id
            LEFT JOIN moz_anno_attributes aa_meta
                ON a_meta.anno_attribute_id = aa_meta.id
                AND aa_meta.name = 'downloads/metaData'
            ORDER BY a_dest.lastModified DESC
        """)
        for src_url, dest, meta, mod_time in cur.fetchall():
            # dest is a file:/// URI — convert to Windows path
            local_path = dest or "N/A"
            if local_path.startswith("file:///"):
                local_path = local_path[8:].replace("/", "\\")

            state_str = "N/A"
            size_str = "N/A"
            if meta:
                try:
                    m = json.loads(meta)
                    state_str = _STATE_MAP.get(m.get("state", -1),
                                               f"State {m.get('state', '?')}")
                    sz = m.get("fileSize")
                    if sz is not None:
                        size_str = f"{sz / 1024:.1f} KB"
                except Exception:
                    pass

            results.append((src_url or "N/A", local_path,
                             _prtime(mod_time), size_str, state_str))
        conn.close()
    except Exception as e:
        results.append(("Error", str(e), "", "", ""))
    finally:
        try:
            os.remove(tmp)
        except OSError:
            pass

    if not results:
        results.append(("Info",
                        "No downloads found — Tor Browser clears download history on exit",
                        "", "", ""))
    return results
