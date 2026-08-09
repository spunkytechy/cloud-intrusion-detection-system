"""routes/auth_routes.py - Authentication routes."""
from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from database.db import db
from models.user import User
from models.audit_log import AuditLog

auth_bp = Blueprint("auth", __name__)


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        remember = request.form.get("remember") == "on"

        user = User.query.filter_by(username=username).first()

        if not user or not user.is_active:
            flash("Invalid username or password.", "danger")
            AuditLog.log(action=AuditLog.ACTION_LOGIN_FAILED,
                         username=username, ip_address=request.remote_addr)
            return render_template("auth/login.html")

        if user.is_locked:
            flash("Account locked due to too many failed attempts. Try again later.", "danger")
            return render_template("auth/login.html")

        if not user.check_password(password):
            user.record_failed_login()
            flash("Invalid username or password.", "danger")
            AuditLog.log(action=AuditLog.ACTION_LOGIN_FAILED,
                         username=username, ip_address=request.remote_addr)
            return render_template("auth/login.html")

        user.record_successful_login()
        login_user(user, remember=remember)
        AuditLog.log(action=AuditLog.ACTION_LOGIN, user_id=user.id,
                     username=user.username, ip_address=request.remote_addr)

        next_page = request.args.get("next")
        return redirect(next_page or url_for("dashboard.index"))

    return render_template("auth/login.html")


@auth_bp.route("/logout")
@login_required
def logout():
    AuditLog.log(action=AuditLog.ACTION_LOGOUT, user_id=current_user.id,
                 username=current_user.username, ip_address=request.remote_addr)
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        email    = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm  = request.form.get("confirm_password", "")

        # Basic validation
        if not username or not email or not password:
            flash("All fields are required.", "danger")
            return render_template("auth/register.html")

        if password != confirm:
            flash("Passwords do not match.", "danger")
            return render_template("auth/register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "danger")
            return render_template("auth/register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already taken.", "danger")
            return render_template("auth/register.html")

        if User.query.filter_by(email=email).first():
            flash("Email already registered.", "danger")
            return render_template("auth/register.html")

        user = User(username=username, email=email, role="viewer", is_active=True)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()

        AuditLog.log(action=AuditLog.ACTION_REGISTER, user_id=user.id,
                     username=user.username, ip_address=request.remote_addr)
        flash("Account created. Please log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")


@auth_bp.route("/profile")
@login_required
def profile():
    return render_template("auth/profile.html", user=current_user)


@auth_bp.route("/change-password", methods=["POST"])
@login_required
def change_password():
    current_pw  = request.form.get("current_password", "")
    new_pw      = request.form.get("new_password", "")
    confirm_pw  = request.form.get("confirm_password", "")

    if not current_user.check_password(current_pw):
        flash("Current password is incorrect.", "danger")
    elif new_pw != confirm_pw:
        flash("New passwords do not match.", "danger")
    elif len(new_pw) < 8:
        flash("Password must be at least 8 characters.", "danger")
    else:
        current_user.set_password(new_pw)
        db.session.commit()
        AuditLog.log(action=AuditLog.ACTION_PASSWORD_CHANGE,
                     user_id=current_user.id, username=current_user.username,
                     ip_address=request.remote_addr)
        flash("Password updated successfully.", "success")

    return redirect(url_for("auth.profile"))
