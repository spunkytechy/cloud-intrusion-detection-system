"""routes/api_routes.py - REST API endpoints + SocketIO /ids namespace."""
from flask import Blueprint, jsonify, current_app
from flask_socketio import Namespace, emit, join_room
from database.db import check_db_connection, get_db_stats
from models.alert import Alert
from models.traffic_log import TrafficLog
from packet_capture.state import get_capture_state
import platform
import psutil
from datetime import datetime, timezone

api_bp = Blueprint("api", __name__)


@api_bp.route("/health", methods=["GET"])
def health_check():
    db_status = check_db_connection()
    try:
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        system = {
            "cpu_percent": cpu,
            "memory_percent": mem.percent,
            "disk_percent": disk.percent,
            "platform": platform.system(),
        }
    except Exception:
        system = {}

    capture = get_capture_state()
    ok = db_status["status"] == "ok"
    return jsonify({
        "status": "ok" if ok else "degraded",
        "app": current_app.config.get("APP_NAME", "Cloud IDS"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": db_status,
        "system": system,
        "capture": capture,
    }), 200 if ok else 503


@api_bp.route("/capture", methods=["GET"])
def capture_status():
    """Return the packet-capture pipeline state."""
    return jsonify(get_capture_state()), 200


@api_bp.route("/stats", methods=["GET"])
def stats():
    try:
        return jsonify({
            "status": "ok",
            "data": get_db_stats(),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }), 200
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 500


@api_bp.route("/alerts/recent", methods=["GET"])
def recent_alerts():
    return jsonify([a.to_dict() for a in Alert.get_unacknowledged(limit=20)]), 200


@api_bp.route("/traffic/recent", methods=["GET"])
def recent_traffic():
    return jsonify([l.to_dict() for l in TrafficLog.get_recent(limit=50)]), 200


class IDSNamespace(Namespace):
    """WebSocket namespace /ids — real-time dashboard updates."""

    def on_connect(self):
        pass

    def on_disconnect(self):
        pass

    def on_subscribe(self, data):
        join_room(data.get("room", "general"))

    def on_ping(self):
        emit("pong", {"time": datetime.now(timezone.utc).isoformat()})


def register_socketio(socketio, app):
    """Register the /ids namespace and launch the background dashboard emitter."""
    socketio.on_namespace(IDSNamespace("/ids"))

    def background_emitter():
        """Emit packet, system, and capture telemetry on a fixed cadence."""
        last_seen = 0
        last_total = 0
        tick = 0
        state = {"last_total": 0, "tick": 0}

        while True:
            socketio.sleep(1)
            tick += 1
            try:
                capture_state = get_capture_state()
                seen = int(capture_state.get("packets_seen", 0))
                delta = max(0, seen - last_seen)
                last_seen = seen

                socketio.emit(
                    "packet_count",
                    {"count": delta, "total": last_total or seen},
                    namespace="/ids",
                )

                if tick % 5 == 0:
                    socketio.emit(
                        "system_stats",
                        {
                            "cpu": psutil.cpu_percent(),
                            "memory": psutil.virtual_memory().percent,
                        },
                        namespace="/ids",
                    )

                if tick % 10 == 0:
                    try:
                        with app.app_context():
                            last_total = TrafficLog.query.count()
                    except Exception:
                        pass
                    socketio.emit("capture_status", capture_state, namespace="/ids")

                state["tick"] += 1
                if state["tick"] % 5 == 0:
                    state["last_total"] = last_total or seen
            except Exception:
                pass

    socketio.start_background_task(background_emitter)
