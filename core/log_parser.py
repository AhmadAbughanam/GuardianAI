# core/log_parser.py

import sqlite3
import os
import json
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "logs.db")


def init_db():
    """Initialize the database and create table if not exists."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            ip TEXT,
            mac TEXT,
            hostname TEXT,
            open_ports TEXT
        )
    """
    )
    conn.commit()
    conn.close()


def save_scan_results(devices: list):
    """
    Save full scan results to the database.
    :param devices: List of dicts from scanner.full_scan()
    """
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    timestamp = datetime.now().isoformat()

    for device in devices:
        cursor.execute(
            """
            INSERT INTO scans (timestamp, ip, mac, hostname, open_ports)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                timestamp,
                device.get("ip"),
                device.get("mac"),
                device.get("hostname"),
                json.dumps(device.get("open_ports", [])),
            ),
        )
    conn.commit()
    conn.close()


def fetch_recent_logs(limit=10):
    """
    Fetch recent scan logs from the database.
    :param limit: Max number of entries
    :return: List of dicts with scan data
    """
    init_db()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        SELECT timestamp, ip, mac, hostname, open_ports
        FROM scans
        ORDER BY timestamp DESC
        LIMIT ?
    """,
        (limit,),
    )
    rows = cursor.fetchall()
    conn.close()

    logs = []
    for row in rows:
        logs.append(
            {
                "timestamp": row[0],
                "ip": row[1],
                "mac": row[2],
                "hostname": row[3],
                "open_ports": json.loads(row[4]),
            }
        )
    return logs


def format_for_display(log):
    """
    Convert a log dict to a clean display string.
    :param log: dict from fetch_recent_logs
    :return: str
    """
    return (
        f"[{log['timestamp']}]\n"
        f"IP: {log['ip']}, MAC: {log['mac']}, Hostname: {log['hostname']}\n"
        f"Open Ports: {', '.join(map(str, log['open_ports']))}\n"
    )


# Test it
if __name__ == "__main__":
    init_db()
    sample = [
        {
            "ip": "192.168.1.10",
            "mac": "AA:BB:CC:DD:EE:FF",
            "hostname": "test-device",
            "open_ports": [22, 80, 443],
        }
    ]
    save_scan_results(sample)
    logs = fetch_recent_logs(5)
    for log in logs:
        print(format_for_display(log))
