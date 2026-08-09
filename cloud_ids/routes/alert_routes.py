"""routes/alert_routes.py - Alert management routes."""
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from database.db import db
from models.alert import Alert
from models.audit_log import AuditLog

alert_bp = Blueprint("alerts", __name__)


@alert_bp.route("/")
@login_required
def index():
    page     = request.args.get("page", 1, type=int)
    severity = request.args.get("severity", "")
    status   = request.args.get("status", "")

    q = Alert.query.order_by(Alert.time_detected.desc())
    if severity:
        q = q.filter_by(severity=severity)
    if status == "unack":
        q = q.filter_by(acknowledged=False, false_positive=False)
    elif status == "resolved":
        q = q.filter_by(resolved=True)

    alerts   = q.paginate(page=page, per_page=25, error_out=False)
    counts   = Alert.count_by_severity()
    return render_template("dashboard/alerts.html",
                           alerts=alerts, counts=counts,
                           severity=severity, status=status)


@alert_bp.route("/<int:alert_id>/acknowledge", methods=["POST"])
@login_required
def acknowledge(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.acknowledge(current_user.username)
    AuditLog.log(action=AuditLog.ACTION_ALERT_ACK, user_id=current_user.id,
                 username=current_user.username, target=f"Alert:{alert_id}",
                 ip_address=request.remote_addr)
    flash("Alert acknowledged.", "success")
    return redirect(url_for("alerts.index"))


@alert_bp.route("/<int:alert_id>/resolve", methods=["POST"])
@login_required
def resolve(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.mark_resolved()
    AuditLog.log(action=AuditLog.ACTION_ALERT_RESOLVED, user_id=current_user.id,
                 username=current_user.username, target=f"Alert:{alert_id}",
                 ip_address=request.remote_addr)
    flash("Alert marked as resolved.", "success")
    return redirect(url_for("alerts.index"))


@alert_bp.route("/<int:alert_id>/false-positive", methods=["POST"])
@login_required
def false_positive(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    alert.mark_false_positive()
    AuditLog.log(action=AuditLog.ACTION_ALERT_FP, user_id=current_user.id,
                 username=current_user.username, target=f"Alert:{alert_id}",
                 ip_address=request.remote_addr)
    flash("Alert marked as false positive.", "info")
    return redirect(url_for("alerts.index"))


@alert_bp.route("/<int:alert_id>/delete", methods=["POST"])
@login_required
def delete(alert_id):
    if not current_user.is_admin():
        flash("Admin access required.", "danger")
        return redirect(url_for("alerts.index"))
    alert = Alert.query.get_or_404(alert_id)
    db.session.delete(alert)
    db.session.commit()
    flash("Alert deleted.", "warning")
    return redirect(url_for("alerts.index"))
