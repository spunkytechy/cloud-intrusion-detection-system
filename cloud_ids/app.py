"""
app.py - Flask Application Factory
====================================
Entry point for the Cloud Intrusion Detection System.

Uses the Application Factory Pattern so that:
  - Multiple instances can be created (e.g., for testing)
  - Extensions are initialised once and shared
  - Blueprints are registered cleanly
  - Circular imports are avoided

Usage:
    # Development
    flask run

    # Production
    gunicorn "app:create_app()" -w 4 -b 0.0.0.0:5000

    # Direct run
    python app.py
"""

import os
import logging
from logging.handlers import RotatingFileHandler

from flask import Flask, jsonify, render_template
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_mail import Mail
from flask_migrate import Migrate
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import JWTManager

from config import get_config

# ==============================================================================
# Extension instances
# NOTE: db is imported from database.db — ONE shared SQLAlchemy instance only.
#       All models also import db from database.db to avoid the duplicate-
#       instance error ("Did you forget to call init_app?").
# ==============================================================================
from database.db import db              # single shared SQLAlchemy instance
login_manager = LoginManager()          # session-based authentication
socketio = SocketIO()                   # real-time WebSocket communication
mail = Mail()                           # SMTP email for alert notifications
migrate = Migrate()                     # Alembic database migrations
csrf = CSRFProtect()                    # CSRF protection for all forms
jwt = JWTManager()                      # JWT token authentication (API routes)
limiter = Limiter(                      # rate limiting (anti-brute-force)
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
)


# ==============================================================================
# APPLICATION FACTORY
# ==============================================================================
def create_app(config_class=None) -> Flask:
    """
    Create and configure the Flask application.

    Args:
        config_class: Optional config class override. Defaults to the class
                      selected by FLASK_ENV via get_config().

    Returns:
        Flask: Fully configured Flask application instance.
    """
    # 1. Create Flask instance
    app = Flask(
        __name__,
        template_folder="templates",
        static_folder="static",
    )

    # 2. Load configuration
    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)

    # 3. Set up structured logging (before anything else uses app.logger)
    _configure_logging(app)

    # 4. Initialise extensions
    _init_extensions(app)

    # 5. Register Blueprints (routes)
    _register_blueprints(app)

    # 6. Register global error handlers
    _register_error_handlers(app)

    # 7. Register shell context for `flask shell`
    _register_shell_context(app)

    # 8. Create DB tables and seed data on first run
    with app.app_context():
        _init_database(app)

    # 9. Register SocketIO namespace + background stats task
    from routes.api_routes import register_socketio
    register_socketio(socketio, app)

    # 10. Start packet capture + detection engine (background threads)
    _start_capture(app)

    app.logger.info("Cloud IDS application started successfully.")
    return app


# ==============================================================================
# PRIVATE HELPERS
# ==============================================================================

def _configure_logging(app: Flask) -> None:
    """
    Set up rotating file handler + stream handler for the application logger.
    Also wires ALL module-level loggers (logging.getLogger(__name__)) to the
    same handlers so detection/alert/sniffer output appears in the log file.
    """
    log_level = getattr(
        logging, app.config.get("LOG_LEVEL", "DEBUG").upper(), logging.DEBUG
    )
    log_file  = app.config.get("LOG_FILE", "logs/cloud_ids.log")
    max_bytes = app.config.get("LOG_MAX_BYTES", 10 * 1024 * 1024)
    backup    = app.config.get("LOG_BACKUP_COUNT", 10)

    os.makedirs(os.path.dirname(log_file), exist_ok=True)

    formatter = logging.Formatter(
        "[%(asctime)s] %(levelname)s %(name)s (%(funcName)s:%(lineno)d): %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(
        log_file, maxBytes=max_bytes, backupCount=backup, encoding="utf-8"
    )
    file_handler.setLevel(log_level)
    file_handler.setFormatter(formatter)

    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(log_level)
    stream_handler.setFormatter(formatter)

    # ── Wire the ROOT logger so every module's getLogger(__name__) is captured
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    # Remove any existing handlers to avoid duplicate output
    root_logger.handlers.clear()
    root_logger.addHandler(file_handler)
    root_logger.addHandler(stream_handler)

    # Flask's own logger delegates to root — just set its level
    app.logger.setLevel(log_level)
    app.logger.propagate = True   # let it flow to root

    app.logger.info(
        "Logging initialised. Level: %s | File: %s",
        app.config.get("LOG_LEVEL", "DEBUG"),
        log_file,
    )


def _init_extensions(app: Flask) -> None:
    """
    Bind all Flask extensions to the application instance.
    Called once per app creation inside create_app().
    """
    # db is the shared instance imported at module level from database.db
    db.init_app(app)
    migrate.init_app(app, db)
    login_manager.init_app(app)
    socketio.init_app(
        app,
        cors_allowed_origins=app.config.get("SOCKETIO_CORS_ALLOWED_ORIGINS", "*"),
        async_mode=app.config.get("SOCKETIO_ASYNC_MODE", "threading"),
        logger=False,
        engineio_logger=False,
    )
    mail.init_app(app)
    csrf.init_app(app)
    jwt.init_app(app)

    # Wire limiter to the storage backend defined in config (memory:// by default)
    limiter._storage_uri = app.config.get("RATELIMIT_STORAGE_URL", "memory://")
    limiter.init_app(app)

    # Flask-Login settings
    login_manager.login_view = app.config.get("LOGIN_VIEW", "auth.login")
    login_manager.login_message = app.config.get(
        "LOGIN_MESSAGE", "Please log in to access this page."
    )
    login_manager.login_message_category = app.config.get(
        "LOGIN_MESSAGE_CATEGORY", "warning"
    )

    # User loader — tells Flask-Login how to reload a user from the session
    from models.user import User

    @login_manager.user_loader
    def load_user(user_id: str):
        """Load user by primary key from the database."""
        return db.session.get(User, int(user_id))

    app.logger.info("All extensions initialised.")


def _register_blueprints(app: Flask) -> None:
    """
    Register all application blueprints (route groups).
    """
    from routes.auth_routes import auth_bp
    app.register_blueprint(auth_bp, url_prefix="/auth")

    from routes.dashboard_routes import dashboard_bp
    app.register_blueprint(dashboard_bp, url_prefix="/dashboard")

    from routes.alert_routes import alert_bp
    app.register_blueprint(alert_bp, url_prefix="/alerts")

    from routes.log_routes import log_bp
    app.register_blueprint(log_bp, url_prefix="/logs")

    from routes.rule_routes import rule_bp
    app.register_blueprint(rule_bp, url_prefix="/rules")

    from routes.api_routes import api_bp
    app.register_blueprint(api_bp, url_prefix="/api/v1")

    # Root redirect → dashboard
    from flask import redirect, url_for

    @app.route("/")
    def index():
        """Redirect root URL to the dashboard."""
        return redirect(url_for("dashboard.index"))

    app.logger.info("All blueprints registered.")


def _register_error_handlers(app: Flask) -> None:
    """
    Register custom HTTP error pages.
    Returns JSON for API requests, HTML for browser requests.
    """
    from flask import request

    def wants_json() -> bool:
        best = request.accept_mimetypes.best_match(
            ["application/json", "text/html"]
        )
        return best == "application/json"

    @app.errorhandler(400)
    def bad_request(e):
        if wants_json():
            return jsonify(error="Bad Request", message=str(e)), 400
        return render_template("errors/400.html", error=e), 400

    @app.errorhandler(401)
    def unauthorized(e):
        if wants_json():
            return jsonify(error="Unauthorized", message=str(e)), 401
        return render_template("errors/401.html", error=e), 401

    @app.errorhandler(403)
    def forbidden(e):
        if wants_json():
            return jsonify(error="Forbidden", message=str(e)), 403
        return render_template("errors/403.html", error=e), 403

    @app.errorhandler(404)
    def not_found(e):
        if wants_json():
            return jsonify(error="Not Found", message=str(e)), 404
        return render_template("errors/404.html", error=e), 404

    @app.errorhandler(429)
    def too_many_requests(e):
        if wants_json():
            return jsonify(error="Too Many Requests", message=str(e)), 429
        return render_template("errors/429.html", error=e), 429

    @app.errorhandler(500)
    def internal_error(e):
        db.session.rollback()
        app.logger.error("Internal Server Error: %s", str(e), exc_info=True)
        if wants_json():
            return jsonify(
                error="Internal Server Error",
                message="An unexpected error occurred.",
            ), 500
        return render_template("errors/500.html", error=e), 500

    app.logger.info("Error handlers registered.")


def _register_shell_context(app: Flask) -> None:
    """
    Push models and db into `flask shell` so they're available without imports.
    """
    @app.shell_context_processor
    def make_shell_context():
        from models.user import User
        from models.traffic_log import TrafficLog
        from models.alert import Alert
        from models.detection_rule import DetectionRule
        from models.audit_log import AuditLog
        return {
            "db": db,
            "User": User,
            "TrafficLog": TrafficLog,
            "Alert": Alert,
            "DetectionRule": DetectionRule,
            "AuditLog": AuditLog,
        }


def _init_database(app: Flask) -> None:
    """
    Create all database tables on first run and seed default data.
    Calls database.db.init_db() which runs create_all() + seed.py.
    _seed_admin() is also called as a safety net for the admin user.
    """
    try:
        from database.db import init_db
        init_db(app)
        app.logger.info("Database tables verified / created.")
        _seed_admin(app)
    except Exception as exc:
        app.logger.error(
            "Database initialisation failed: %s", exc, exc_info=True
        )


def _seed_admin(app: Flask) -> None:
    """
    Create the default admin user if no users exist.
    Reads credentials from app.config (sourced from .env).
    """
    from models.user import User

    try:
        if User.query.count() == 0:
            admin = User(
                username=app.config["ADMIN_USERNAME"],
                email=app.config["ADMIN_EMAIL"],
                role="admin",
                is_active=True,
            )
            admin.set_password(app.config["ADMIN_PASSWORD"])
            db.session.add(admin)
            db.session.commit()
            app.logger.info(
                "Admin account seeded: %s", app.config["ADMIN_USERNAME"]
            )
        else:
            app.logger.info("Admin seeding skipped — users already exist.")
    except Exception as exc:
        db.session.rollback()
        app.logger.warning("Admin seeding skipped: %s", exc)


def _start_capture(app: Flask) -> None:
    """
    Start the PacketSniffer and PacketAnalyzer background threads.

    - PacketSniffer captures raw packets from the network interface
      and pushes them into the shared packet_queue.
    - PacketAnalyzer drains that queue, parses each packet, saves a
      TrafficLog row, and runs it through the DetectionEngine.

    Both threads are daemon threads so they die automatically when
    the main process exits. Sniffer failures (e.g. missing Npcap on
    Windows, or insufficient permissions) are caught and logged — they
    will NOT crash the web application.
    """
    import threading

    # ── Start Analyzer first (must be ready before sniffer produces packets)
    try:
        from packet_capture.analyzer import PacketAnalyzer
        analyzer = PacketAnalyzer(app)
        analyzer.start()
        app.logger.info("PacketAnalyzer thread started.")
    except Exception as exc:
        app.logger.error("Failed to start PacketAnalyzer: %s", exc)
        return  # no point starting sniffer if analyzer won't run

    # ── Start Sniffer
    try:
        from packet_capture.sniffer import get_sniffer_instance
        sniffer = get_sniffer_instance(app)
        sniffer.start()
        app.logger.info(
            "PacketSniffer thread started on interface: %s",
            sniffer.interface or "default",
        )
    except Exception as exc:
        # Sniffer failure is non-fatal — dashboard still works without live capture
        app.logger.warning(
            "PacketSniffer could not start (Npcap installed? Running as admin?): %s",
            exc,
        )


# ==============================================================================
# DIRECT RUN ENTRY POINT
# `python app.py` — runs via socketio.run() for WebSocket support
# ==============================================================================
if __name__ == "__main__":
    app = create_app()
    port = int(os.environ.get("APP_PORT", 5000))

    app.logger.info("Starting Cloud IDS on port %d", port)

    # IMPORTANT: use_reloader=False + debug=False prevents the double-bind
    # WinError 10048 that occurs when Flask reloader tries to re-spawn the
    # gevent/threading server on the same port.
    socketio.run(
        app,
        host="127.0.0.1",   # localhost only; use Nginx/ngrok for external access
        port=port,
        debug=False,
        use_reloader=False,
        log_output=True,
    )
