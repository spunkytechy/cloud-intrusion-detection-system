"""routes/rule_routes.py - Detection rule management routes."""
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_login import login_required, current_user
from database.db import db
from models.detection_rule import DetectionRule
from models.audit_log import AuditLog

rule_bp = Blueprint("rules", __name__)


@rule_bp.route("/")
@login_required
def index():
    rules = DetectionRule.query.order_by(DetectionRule.id).all()
    return render_template("dashboard/rules.html", rules=rules)


@rule_bp.route("/<int:rule_id>/toggle", methods=["POST"])
@login_required
def toggle(rule_id):
    if not current_user.is_analyst():
        flash("Insufficient permissions.", "danger")
        return redirect(url_for("rules.index"))
    rule = DetectionRule.query.get_or_404(rule_id)
    state = rule.toggle()
    AuditLog.log(action=AuditLog.ACTION_RULE_TOGGLED, user_id=current_user.id,
                 username=current_user.username, target=f"Rule:{rule_id}",
                 ip_address=request.remote_addr,
                 details={"rule_name": rule.rule_name, "enabled": state})
    flash(f"Rule '{rule.rule_name}' {'enabled' if state else 'disabled'}.", "info")
    return redirect(url_for("rules.index"))


@rule_bp.route("/<int:rule_id>/edit", methods=["POST"])
@login_required
def edit(rule_id):
    if not current_user.is_admin():
        flash("Admin access required.", "danger")
        return redirect(url_for("rules.index"))
    rule = DetectionRule.query.get_or_404(rule_id)
    rule.threshold = request.form.get("threshold", rule.threshold, type=int)
    rule.window    = request.form.get("window", rule.window, type=int)
    rule.severity  = request.form.get("severity", rule.severity)
    db.session.commit()
    AuditLog.log(action=AuditLog.ACTION_RULE_UPDATED, user_id=current_user.id,
                 username=current_user.username, target=f"Rule:{rule_id}",
                 ip_address=request.remote_addr)
    flash(f"Rule '{rule.rule_name}' updated.", "success")
    return redirect(url_for("rules.index"))
