"""SQLite persistence for connected-network security score history."""

import json
import os
import shutil
import sqlite3
import sys
from contextlib import closing
from datetime import datetime
from pathlib import Path


if getattr(sys, "frozen", False):
    app_data = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    DATABASE_PATH = app_data / "WISE" / "wise_scans.db"
else:
    # Keep source-run history with this checkout. The database is ignored by Git,
    # so a fresh clone starts empty while rescans in this checkout remain saved.
    DATABASE_PATH = Path(__file__).with_name("wise_scans.db")


def _database_template_path():
    if getattr(sys, "frozen", False):
        bundle_root = Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
        return bundle_root / "data" / "wise_scans.db"
    return Path(__file__).with_name("data") / "wise_scans.db"


def _connect():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize_database():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    template_path = _database_template_path()
    if not DATABASE_PATH.exists() and template_path.is_file():
        shutil.copyfile(template_path, DATABASE_PATH)
    with closing(_connect()) as connection, connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                ssid TEXT NOT NULL DEFAULT '<Unknown>',
                network_key TEXT NOT NULL DEFAULT '<Unknown>',
                score INTEGER NOT NULL DEFAULT 0,
                protocol_score INTEGER NOT NULL DEFAULT 0,
                company_score INTEGER NOT NULL DEFAULT 0,
                other_score INTEGER NOT NULL DEFAULT 0,
                connection_json TEXT NOT NULL DEFAULT '{}',
                score_json TEXT NOT NULL DEFAULT '{}',
                recommended_channel INTEGER,
                congestion_status TEXT,
                environment_json TEXT NOT NULL DEFAULT '{}'
            )"""
        )
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
        for name, definition in (
            ("ssid", "TEXT NOT NULL DEFAULT '<Unknown>'"),
            ("network_key", "TEXT NOT NULL DEFAULT '<Unknown>'"),
            ("score", "INTEGER NOT NULL DEFAULT 0"),
            ("protocol_score", "INTEGER NOT NULL DEFAULT 0"),
            ("company_score", "INTEGER NOT NULL DEFAULT 0"),
            ("other_score", "INTEGER NOT NULL DEFAULT 0"),
            ("connection_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("score_json", "TEXT NOT NULL DEFAULT '{}'"),
            ("recommended_channel", "INTEGER"),
            ("congestion_status", "TEXT"),
            ("environment_json", "TEXT NOT NULL DEFAULT '{}'"),
        ):
            if name not in columns:
                connection.execute(f"ALTER TABLE scans ADD COLUMN {name} {definition}")
        # An earlier WISE version stored nearby networks in a separate table.
        # Backfill compatible SSIDs before adding the rescan lookup index.
        connection.execute(
            "UPDATE scans SET network_key = lower(ssid) "
            "WHERE network_key = '<Unknown>' AND ssid <> '<Unknown>'"
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_network_time ON scans(network_key, scanned_at, id)"
        )


def save_scan(connection_info, score_info, update_id=None):
    """Save a scan or update its user-entered assessment; return its id and prior scan."""
    ssid = str(connection_info.get("ssid", "<Unknown>"))
    network_key = ssid.casefold()
    scanned_at = datetime.now().astimezone().isoformat(timespec="seconds")
    with closing(_connect()) as connection, connection:
        previous = connection.execute(
            "SELECT * FROM scans WHERE network_key = ? ORDER BY scanned_at DESC, id DESC LIMIT 1",
            (network_key,),
        ).fetchone()
        if update_id is not None:
            existing = connection.execute("SELECT network_key FROM scans WHERE id = ?", (update_id,)).fetchone()
            if existing is not None and existing["network_key"] == network_key:
                connection.execute(
                    """UPDATE scans SET score = ?, protocol_score = ?, company_score = ?, other_score = ?,
                       connection_json = ?, score_json = ? WHERE id = ?""",
                    (score_info["total"], score_info["protocol"], score_info["company_and_password"],
                     score_info["other"], json.dumps(connection_info, ensure_ascii=False),
                     json.dumps(score_info, ensure_ascii=False), update_id),
                )
                return {"id": update_id, "previous": dict(previous) if previous else None, "updated": True}
        cursor = connection.execute(
            """INSERT INTO scans
               (scanned_at, ssid, network_key, score, protocol_score, company_score, other_score,
                connection_json, score_json, recommended_channel, congestion_status, environment_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (scanned_at, ssid, network_key, score_info["total"], score_info["protocol"],
             score_info["company_and_password"], score_info["other"],
             json.dumps(connection_info, ensure_ascii=False), json.dumps(score_info, ensure_ascii=False),
             None, None, json.dumps({}, ensure_ascii=False)),
        )
        return {"id": cursor.lastrowid, "previous": dict(previous) if previous else None}


def list_scans():
    with closing(_connect()) as connection, connection:
        return [dict(row) for row in connection.execute(
            "SELECT id, scanned_at, ssid, score, protocol_score, company_score, other_score "
            "FROM scans ORDER BY scanned_at DESC, id DESC"
        )]


def get_scan(scan_id):
    with closing(_connect()) as connection, connection:
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
        if row is None:
            return None
        result = dict(row)
        result["connection"] = json.loads(result.pop("connection_json"))
        result["score_details"] = json.loads(result.pop("score_json"))
        return result


def delete_scan(scan_id):
    with closing(_connect()) as connection, connection:
        cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0


def delete_all_scans():
    with closing(_connect()) as connection, connection:
        cursor = connection.execute("DELETE FROM scans")
        return cursor.rowcount
