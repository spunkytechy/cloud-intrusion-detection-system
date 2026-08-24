"""routes/dashboard_routes.py - Dashboard, Stats, Settings, Export."""
from flask import (Blueprint, render_template, redirect, url_for,
                   flash, request, Response, current_app)
from flask_login import login_required, current_user
from database.db import db
from models.alert import Alert
from models.detection_rule import DetectionRule
from models.traffic_log import TrafficLog
from models.user import User
from models.audit_log import AuditLog
from packet_capture.state import get_capture_state
import csv, io
from datetime import datetime, timezone, timedelta

dashboard_bp = Blueprint("dashboard", __name__)


@dashboard_bp.route("/")
@dashboard_bp.route("/index")
@login_required
def index():
    total_packets   = TrafficLog.query.count()
    total_alerts    = Alert.query.count()
    active_threats  = Alert.query.filter_by(
        acknowledged=False, resolved=False, false_positive=False).count()
    total_rules     = DetectionRule.query.filter_by(enabled=True).count()
    unack_alerts    = Alert.get_unacknowledged(limit=5)
    recent_logs     = TrafficLog.get_recent(limit=10)
    severity_counts = Alert.count_by_severity()
    threat_counts   = Alert.count_by_threat_type()
    top_ips         = TrafficLog.get_top_source_ips(limit=5)
    capture_state   = get_capture_state()
    return render_template("dashboard/index.html",
        total_packets=total_packets,
        total_alerts=total_alerts,
        active_threats=active_threats,
        total_rules=total_rules,
        unack_alerts=unack_alerts,
        recent_logs=recent_logs,
        severity_counts=severity_counts,
        threat_counts=threat_counts,
        top_ips=top_ips,
        capture_state=capture_state,
    )


@dashboard_bp.route("/stats")
@login_required
def stats():
    since = datetime.now(timezone.utc) - timedelta(hours=24)

    if db.engine.dialect.name == "postgresql":
        from sqlalchemy import func as f
        hourly = (
            db.session.query(
                f.date_trunc("hour", TrafficLog.timestamp).label("hour"),
                f.count(TrafficLog.id).label("count")
            )
            .filter(TrafficLog.timestamp >= since)
            .group_by("hour").order_by("hour").all()
        )
        labels  = [r.hour.strftime("%H:%M") if r.hour else "" for r in hourly]
        traffic = [r.count for r in hourly]
    else:
        labels  = ["Total"]
        traffic = [TrafficLog.query.filter(TrafficLog.timestamp >= since).count()]

    protocol_dist = TrafficLog.get_protocol_distribution()
    threat_counts = Alert.count_by_threat_type()
    sev_counts    = Alert.count_by_severity()

    return render_template("dashboard/stats.html",
        labels=labels,
        traffic=traffic,
        proto_labels=[r[0] for r in protocol_dist],
        proto_counts=[r[1] for r in protocol_dist],
        threat_counts=threat_counts,
        sev_counts=sev_counts,
    )


@dashboard_bp.route("/settings", methods=["GET", "POST"])
@login_required
def settings():
    if not current_user.is_admin():
        flash("Admin access required.", "danger")
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        action = request.form.get("action")

        if action == "add_blacklist":
            ip = request.form.get("ip", "").strip()
            if ip:
                bl = current_app.config.get("IP_BLACKLIST", [])
                if ip not in bl:
                    bl.append(ip)
                    current_app.config["IP_BLACKLIST"] = bl
                    flash(f"IP {ip} added to blacklist.", "success")
                else:
                    flash(f"IP {ip} is already blacklisted.", "info")

        elif action == "remove_blacklist":
            ip = request.form.get("ip", "").strip()
            bl = current_app.config.get("IP_BLACKLIST", [])
            if ip in bl:
                bl.remove(ip)
                current_app.config["IP_BLACKLIST"] = bl
                flash(f"IP {ip} removed from blacklist.", "info")

        elif action == "toggle_user":
            uid = request.form.get("user_id", type=int)
            u = db.session.get(User, uid)
            if u and u.id != current_user.id:
                u.is_active = not u.is_active
                db.session.commit()
                flash(f"User {u.username} {'enabled' if u.is_active else 'disabled'}.", "info")

        return redirect(url_for("dashboard.settings"))

    users     = User.query.order_by(User.created_at.desc()).all()
    blacklist = current_app.config.get("IP_BLACKLIST", [])
    return render_template("dashboard/settings.html", users=users, blacklist=blacklist)


@dashboard_bp.route("/export/logs")
@login_required
def export_logs():
    logs = TrafficLog.query.order_by(TrafficLog.timestamp.desc()).limit(1000).all()
    out  = io.StringIO()
    w    = csv.writer(out)
    w.writerow(["ID", "Source IP", "Dest IP", "Protocol", "Port",
                "Size", "Status", "Timestamp"])
    for l in logs:
        w.writerow([l.id, l.source_ip, l.destination_ip, l.protocol,
                    l.port, l.packet_size, l.status,
                    l.timestamp.strftime("%Y-%m-%d %H:%M:%S") if l.timestamp else ""])
    AuditLog.log(action=AuditLog.ACTION_EXPORT, user_id=current_user.id,
                 username=current_user.username, ip_address=request.remote_addr)
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=traffic_logs.csv"})


@dashboard_bp.route("/export/alerts")
@login_required
def export_alerts():
    alerts = Alert.query.order_by(Alert.time_detected.desc()).limit(1000).all()
    out    = io.StringIO()
    w      = csv.writer(out)
    w.writerow(["ID", "Threat Type", "Source IP", "Severity", "Message",
                "Time", "Acknowledged", "Resolved"])
    for a in alerts:
        w.writerow([a.alert_id, a.threat_type, a.source_ip, a.severity, a.message,
                    a.time_detected.strftime("%Y-%m-%d %H:%M:%S") if a.time_detected else "",
                    a.acknowledged, a.resolved])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment;filename=alerts.csv"})
