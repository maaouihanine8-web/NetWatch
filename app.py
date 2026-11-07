"""NetWatch : tableau de bord de surveillance et de sécurité réseau (Flask)."""
import os

from flask import Flask, flash, g, jsonify, redirect, render_template, request, url_for

import alerts as rules
import db
import demo
import scanner

SEVERITY_CSS = {"info": "info", "faible": "low", "moyen": "medium", "élevé": "high"}


def run_scan(conn, target: str, demo_mode: bool) -> dict:
    """Découvre les appareils, scanne leurs ports et génère les alertes."""
    hosts = demo.demo_hosts() if demo_mode else scanner.discover_hosts(target)
    new_devices = 0
    for host in hosts:
        device_id, is_new = db.upsert_device(conn, host)
        if is_new:
            new_devices += 1
            db.add_alert(conn, device_id, "new_device", "info", "Nouvel appareil détecté sur le réseau")
        ports = demo.demo_ports(host["ip"]) if demo_mode else scanner.scan_ports(host["ip"])
        db.replace_ports(conn, device_id, ports)
        db.replace_port_alerts(conn, device_id, rules.evaluate(ports))
    return {"devices": len(hosts), "new": new_devices}


def create_app(db_path: str | None = None, demo_mode: bool | None = None) -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("NETWATCH_SECRET", os.urandom(16))
    app.config["DB_PATH"] = db_path or os.environ.get("NETWATCH_DB", "netwatch.db")
    app.config["DEMO"] = demo_mode if demo_mode is not None else os.environ.get("NETWATCH_DEMO") == "1"
    app.config["DEFAULT_TARGET"] = os.environ.get("NETWATCH_TARGET", "192.168.1.0/24")

    def get_conn():
        if "conn" not in g:
            g.conn = db.connect(app.config["DB_PATH"])
        return g.conn

    @app.teardown_appcontext
    def close_conn(_exc):
        conn = g.pop("conn", None)
        if conn is not None:
            conn.close()

    @app.context_processor
    def helpers():
        return {"css": lambda severity: SEVERITY_CSS.get(severity, "info")}

    @app.get("/")
    def index():
        devices = db.list_devices(get_conn())
        for d in devices:
            d["risk"] = rules.highest_severity(a["severity"] for a in d["alerts"] if a["kind"] == "port")
        all_alerts = db.list_alerts(get_conn())
        stats = {
            "devices": len(devices),
            "open_ports": sum(len(d["ports"]) for d in devices),
            "high": sum(1 for a in all_alerts if a["severity"] == "élevé"),
            "alerts": len(all_alerts),
        }
        return render_template("index.html", devices=devices, alerts=all_alerts, stats=stats,
                               target=app.config["DEFAULT_TARGET"], demo=app.config["DEMO"])

    @app.post("/scan")
    def scan():
        target = request.form.get("target", app.config["DEFAULT_TARGET"])
        try:
            if not app.config["DEMO"]:
                target = scanner.validate_target(target)
            result = run_scan(get_conn(), target, app.config["DEMO"])
            flash(f"Scan terminé : {result['devices']} appareil(s), {result['new']} nouveau(x).", "ok")
        except scanner.ScanError as exc:
            flash(str(exc), "error")
        return redirect(url_for("index"))

    @app.get("/api/devices")
    def api_devices():
        return jsonify(db.list_devices(get_conn()))

    @app.get("/api/alerts")
    def api_alerts():
        return jsonify(db.list_alerts(get_conn()))

    return app


if __name__ == "__main__":
    create_app().run(host="127.0.0.1", port=5000, debug=False)
