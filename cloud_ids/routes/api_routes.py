"""routes/api_routes.py - REST API endpoints + SocketIO /ids namespace."""
from flask import Blueprint, jsonify, current_app
from flask_socketio import Namespace, emit, join_room
from database.db import check_db_connection, get_db_stats
from models.alert import Alert
from models.traffic_log import TrafficLog
import psutil, platform
from datetime import datetime, timezone

api_bp = Blueprint("api", __name__)


# ── REST endpoints ────────────────────────────────────────────────────────────

@api_bp.route("/health", methods=["GET"])
def health_check():
    db_status = check_db_connection()
    try:
        cpu    = psutil.cpu_percent(interval=0.1)
        mem    = psutil.virtual_memory()
        disk   = psutil.disk_usage("/")
        system = {"cpu_percent": cpu, "memory_percent": mem.percent,
                  "disk_percent": disk.percent, "platform": platform.system()}
    except Exception:
        system = {}
    return jsonify({
        "status":    "ok" if db_status["status"] == "ok" else "degraded",
        "app":       current_app.config.get("APP_NAME", "Cloud IDS"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database":  db_status,
        "system":    system,
    }), 200 if db_status["status"] == "ok" else 503


@api_bp.route("/stats", methods=["GET"])
def stats():
    try:
        return jsonify({"status": "ok", "data": get_db_stats(),
                        "timestamp": datetime.now(timezone.utc).isoformat()}), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@api_bp.route("/alerts/recent", methods=["GET"])
def recent_alerts():
    return jsonify([a.to_dict() for a in Alert.get_unacknowledged(limit=20)]), 200


@api_bp.route("/traffic/recent", methods=["GET"])
def recent_traffic():
    return jsonify([l.to_dict() for l in TrafficLog.get_recent(limit=50)]), 200


# ── SocketIO namespace ────────────────────────────────────────────────────────

class IDSNamespace(Namespace):
    """WebSocket namespace /ids — real-time dashboard updates."""

    def on_connect(self):
        pass  # silent connect

    def on_disconnect(self):
        pass

    def on_subscribe(self, data):
        join_room(data.get("room", "general"))

    def on_ping(self):
        emit("pong", {"time": datetime.now(timezone.utc).isoformat()})


def register_socketio(socketio, app):
    """
    Register the /ids namespace and launch the background stats emitter.

    Args:
        socketio : the shared SocketIO instance
        app      : the Flask app instance (captured in closure so the
                   background thread has an app context)
    """
    socketio.on_namespace(IDSNamespace("/ids"))

    def background_stats():
        """Emit packet_count every second and system_stats every 5 seconds."""
        last_total = 0
        tick       = 0

        while True:
            socketio.sleep(1)
            try:
                with app.app_context():
                    total     = TrafficLog.query.count()
                    new_count = max(0, total - last_total)
                    last_total = total
                    tick      += 1

                    socketio.emit("packet_count",
                                  {"count": new_count, "total": total},
                                  namespace="/ids")

                    if tick % 5 == 0:
                        socketio.emit("system_stats", {
                            "cpu":    psutil.cpu_percent(),
                            "memory": psutil.virtual_memory().percent,
                        }, namespace="/ids")
            except Exception:
                pass  # never let the background thread die

    socketio.start_background_task(background_stats)
