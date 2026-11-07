"""Base de données SQLite : appareils, ports ouverts et alertes."""
import sqlite3
from datetime import datetime

SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip TEXT NOT NULL UNIQUE,
    mac TEXT,
    vendor TEXT,
    hostname TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS ports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    service TEXT,
    product TEXT,
    UNIQUE(device_id, port, protocol)
);
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id INTEGER NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(SCHEMA)
    return conn


def upsert_device(conn, host: dict) -> tuple[int, bool]:
    """Ajoute ou met à jour un appareil. Retourne (id, est_nouveau)."""
    row = conn.execute("SELECT id FROM devices WHERE ip = ?", (host["ip"],)).fetchone()
    if row:
        conn.execute(
            "UPDATE devices SET mac = COALESCE(?, mac), vendor = COALESCE(?, vendor), "
            "hostname = COALESCE(?, hostname), last_seen = ? WHERE id = ?",
            (host.get("mac"), host.get("vendor"), host.get("hostname"), _now(), row["id"]),
        )
        conn.commit()
        return row["id"], False
    cur = conn.execute(
        "INSERT INTO devices (ip, mac, vendor, hostname, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)",
        (host["ip"], host.get("mac"), host.get("vendor"), host.get("hostname"), _now(), _now()),
    )
    conn.commit()
    return cur.lastrowid, True


def replace_ports(conn, device_id: int, ports: list[dict]) -> None:
    conn.execute("DELETE FROM ports WHERE device_id = ?", (device_id,))
    conn.executemany(
        "INSERT OR IGNORE INTO ports (device_id, port, protocol, service, product) VALUES (?, ?, ?, ?, ?)",
        [(device_id, p["port"], p["protocol"], p["service"], p["product"]) for p in ports],
    )
    conn.commit()


def replace_port_alerts(conn, device_id: int, alerts: list[dict]) -> None:
    """Remplace les alertes de ports d'un appareil (évite les doublons à chaque scan)."""
    conn.execute("DELETE FROM alerts WHERE device_id = ? AND kind = 'port'", (device_id,))
    conn.executemany(
        "INSERT INTO alerts (device_id, kind, severity, message, created_at) VALUES (?, ?, ?, ?, ?)",
        [(device_id, a["kind"], a["severity"], a["message"], _now()) for a in alerts],
    )
    conn.commit()


def add_alert(conn, device_id: int, kind: str, severity: str, message: str) -> None:
    conn.execute(
        "INSERT INTO alerts (device_id, kind, severity, message, created_at) VALUES (?, ?, ?, ?, ?)",
        (device_id, kind, severity, message, _now()),
    )
    conn.commit()


def list_devices(conn) -> list[dict]:
    devices = []
    for d in conn.execute("SELECT * FROM devices ORDER BY ip"):
        device = dict(d)
        device["ports"] = [dict(p) for p in conn.execute(
            "SELECT port, protocol, service, product FROM ports WHERE device_id = ? ORDER BY port", (d["id"],))]
        device["alerts"] = [dict(a) for a in conn.execute(
            "SELECT severity, message, kind, created_at FROM alerts WHERE device_id = ?", (d["id"],))]
        devices.append(device)
    return devices


def list_alerts(conn) -> list[dict]:
    rows = conn.execute(
        "SELECT a.severity, a.message, a.kind, a.created_at, d.ip "
        "FROM alerts a JOIN devices d ON d.id = a.device_id ORDER BY a.created_at DESC, a.id DESC"
    )
    return [dict(r) for r in rows]
