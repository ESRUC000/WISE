"""Computer-local SQLite persistence for WISE guest sessions."""

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path


LOCAL_DATA_PATH = Path(os.environ.get("LOCALAPPDATA") or Path.home() / ".local" / "share")
DATABASE_PATH = LOCAL_DATA_PATH / "WISE" / "guest_scans.db"


def _connect():
    DATABASE_PATH.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    connection.execute("PRAGMA secure_delete = ON")
    return connection


def initialize_database():
    with closing(_connect()) as connection, connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                ssid TEXT NOT NULL DEFAULT '<Unknown>',
                network_key TEXT NOT NULL,
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
        connection.execute(
            """CREATE TABLE IF NOT EXISTS device_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scanned_at TEXT NOT NULL,
                interface TEXT NOT NULL,
                subnet TEXT NOT NULL,
                gateway_ip TEXT,
                devices_json TEXT NOT NULL DEFAULT '[]'
            )"""
        )


def save_scan(connection_info, score_info, update_id=None, user_id=None, separate=False):
    ssid = str(connection_info.get("ssid", "<Unknown>"))
    bssid = str(connection_info.get("bssid") or "").strip().casefold()
    if ssid.strip().casefold() in ("", "<hidden>", "<unknown>"):
        network_key = f"bssid:{bssid}" if bssid else f"hidden:{datetime.now().timestamp()}"
    else:
        network_key = f"ssid:{ssid.casefold()}"
    scanned_at = datetime.now().astimezone().isoformat(timespec="seconds")
    environment = connection_info.get("environment") or {}
    values = (
        scanned_at, ssid, network_key, score_info["total"], score_info["protocol"],
        score_info["company_and_password"], score_info["other"],
        json.dumps(connection_info, ensure_ascii=False), json.dumps(score_info, ensure_ascii=False),
        environment.get("recommended_channel"), environment.get("status"),
        json.dumps(environment, ensure_ascii=False),
    )
    with closing(_connect()) as connection, connection:
        previous = connection.execute(
            "SELECT * FROM scans WHERE network_key = ? ORDER BY scanned_at DESC, id DESC LIMIT 1",
            (network_key,),
        ).fetchone()
        existing = None
        if update_id is not None:
            existing = connection.execute("SELECT * FROM scans WHERE id = ?", (update_id,)).fetchone()
        elif previous is not None and not separate:
            existing = previous

        if existing is not None and existing["network_key"] == network_key:
            connection.execute(
                """UPDATE scans SET scanned_at = ?, ssid = ?, network_key = ?, score = ?,
                   protocol_score = ?, company_score = ?, other_score = ?, connection_json = ?,
                   score_json = ?, recommended_channel = ?, congestion_status = ?, environment_json = ?
                   WHERE id = ?""",
                (*values, existing["id"]),
            )
            return {"id": existing["id"], "previous": dict(existing), "updated": True}

        cursor = connection.execute(
            """INSERT INTO scans
               (scanned_at, ssid, network_key, score, protocol_score, company_score, other_score,
                connection_json, score_json, recommended_channel, congestion_status, environment_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            values,
        )
        return {"id": cursor.lastrowid, "previous": dict(previous) if previous else None}


def list_scans(user_id=None):
    with closing(_connect()) as connection:
        return [dict(row) for row in connection.execute(
            "SELECT id, scanned_at, ssid, network_key, score, protocol_score, company_score, other_score "
            "FROM scans ORDER BY scanned_at DESC, id DESC"
        )]


def get_scan(scan_id, user_id=None):
    with closing(_connect()) as connection:
        row = connection.execute("SELECT * FROM scans WHERE id = ?", (scan_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    connection_info = json.loads(result.pop("connection_json"))
    score_details = json.loads(result.pop("score_json"))
    result["environment"] = json.loads(result.pop("environment_json"))
    result["connection"] = connection_info if isinstance(connection_info, dict) else {}
    if isinstance(score_details, dict) and score_details:
        result["score_details"] = score_details
    else:
        protocol = result["protocol_score"]
        company = result["company_score"]
        other = result["other_score"]
        result["score_details"] = {
            "total": result["score"],
            "protocol": protocol,
            "company_and_password": company,
            "other": other,
            "company_network": False,
            "password_policy_ok": False,
            "breakdown": [
                {"category": "Security protocol", "earned": protocol, "possible": 60,
                 "note": "Details were not stored in this scan."},
                {"category": "Company SSID/password", "earned": company, "possible": 20,
                 "note": "Details were not stored in this scan."},
                {"category": "Other safeguards", "earned": other, "possible": 20,
                 "note": "Details were not stored in this scan."},
            ],
        }
    return result


def delete_scan(scan_id, user_id=None):
    with closing(_connect()) as connection, connection:
        cursor = connection.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
        return cursor.rowcount > 0


def delete_all_scans(user_id=None):
    with closing(_connect()) as connection, connection:
        cursor = connection.execute("DELETE FROM scans")
        return cursor.rowcount


def save_device_snapshot(snapshot, user_id=None):
    scanned_at = datetime.now().astimezone().isoformat(timespec="seconds")
    devices = [dict(device) for device in snapshot.get("devices", [])]
    with closing(_connect()) as connection, connection:
        previous = connection.execute(
            "SELECT devices_json FROM device_snapshots ORDER BY scanned_at DESC, id DESC LIMIT 1"
        ).fetchone()
        known_macs = {
            str(device.get("mac", "")).casefold()
            for device in json.loads(previous["devices_json"])
        } if previous else set()
        for device in devices:
            mac = str(device.get("mac", "")).casefold()
            device["is_new"] = bool(previous and mac and mac != "unknown" and mac not in known_macs)
        values = (
            scanned_at, str(snapshot.get("interface", "Unknown")),
            str(snapshot.get("subnet", "Unknown")), snapshot.get("gateway_ip"),
            json.dumps(devices, ensure_ascii=False),
        )
        cursor = connection.execute(
            """INSERT INTO device_snapshots
               (scanned_at, interface, subnet, gateway_ip, devices_json) VALUES (?, ?, ?, ?, ?)""",
            values,
        )
        snapshot_id = cursor.lastrowid
    return {"id": snapshot_id, "scanned_at": scanned_at, "interface": values[1],
            "subnet": values[2], "gateway_ip": values[3], "devices": devices}


def latest_device_snapshot(user_id=None):
    with closing(_connect()) as connection:
        row = connection.execute(
            "SELECT * FROM device_snapshots ORDER BY scanned_at DESC, id DESC LIMIT 1"
        ).fetchone()
    if row is None:
        return None
    result = dict(row)
    result["devices"] = json.loads(result.pop("devices_json"))
    return result