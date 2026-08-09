"""routes/log_routes.py - Traffic log routes."""
from flask import Blueprint, render_template, request
from flask_login import login_required
from models.traffic_log import TrafficLog

log_bp = Blueprint("logs", __name__)


@log_bp.route("/")
@login_required
def index():
    page     = request.args.get("page", 1, type=int)
    protocol = request.args.get("protocol", "")
    status   = request.args.get("status", "")
    src_ip   = request.args.get("src_ip", "")

    q = TrafficLog.query.order_by(TrafficLog.timestamp.desc())
    if protocol:
        q = q.filter_by(protocol=protocol)
    if status:
        q = q.filter_by(status=status)
    if src_ip:
        q = q.filter(TrafficLog.source_ip.ilike(f"%{src_ip}%"))

    logs = q.paginate(page=page, per_page=50, error_out=False)
    return render_template("dashboard/logs.html", logs=logs,
                           protocol=protocol, status=status, src_ip=src_ip)
