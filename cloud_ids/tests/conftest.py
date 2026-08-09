"""
tests/conftest.py - Pytest Fixtures
=====================================
Shared fixtures available to every test module in the suite.

Fixtures provided:
  app         → Flask test application (TestingConfig: SQLite in-memory)
  db_session  → Clean database session, rolled back after each test
  client      → Flask test client (no cookies between requests)
  auth_client → Test client pre-logged-in as admin
  admin_user  → Persisted admin User instance
  analyst_user→ Persisted analyst User instance
  viewer_user → Persisted viewer User instance
  sample_alert       → One Alert row
  sample_traffic_log → One TrafficLog row
  sample_rule        → One DetectionRule row

Isolation strategy:
  - TestingConfig uses SQLite in-memory — never touches the real AWS RDS.
  - Each test gets a fresh transaction that is rolled back on teardown,
    so tests are fully independent with no cleanup code required.
"""

from datetime import datetime, timezone

import pytest

from app import create_app
from config import TestingConfig
from database.db import db as _db


# ==============================================================================
# APPLICATION FIXTURE
# ==============================================================================
@pytest.fixture(scope="session")
def app():
    """
    Create a single Flask application instance for the whole test session.

    Uses TestingConfig which sets:
      - SQLALCHEMY_DATABASE_URI = sqlite:///:memory:
      - WTF_CSRF_ENABLED        = False
      - TESTING                 = True
      - BCRYPT_LOG_ROUNDS       = 4  (fast hashing)
      - MAIL_SUPPRESS_SEND      = True
    """
    _app = create_app(TestingConfig)

    with _app.app_context():
        # Create all tables in the in-memory SQLite database
        _db.create_all()
        yield _app
        # Drop all tables after the session ends
        _db.drop_all()


# ==============================================================================
# DATABASE SESSION FIXTURE
# ==============================================================================
@pytest.fixture(scope="function")
def db_session(app):
    """
    Provide a clean database session for each individual test.

    Strategy:
      - Begin a savepoint (nested transaction) before the test.
      - Roll back to the savepoint after the test completes.
      - This means every test starts with an empty database state
        without needing to drop and recreate tables.
    """
    with app.app_context():
        connection = _db.engine.connect()
        transaction = connection.begin()

        # Bind the session to our controlled connection
        _db.session.bind = connection

        yield _db.session

        # Teardown: roll back everything the test wrote
        _db.session.remove()
        transaction.rollback()
        connection.close()


# ==============================================================================
# HTTP CLIENT FIXTURES
# ==============================================================================
@pytest.fixture(scope="function")
def client(app):
    """
    Unauthenticated Flask test client.

    Use this for testing public routes (login page, health check, etc.).
    """
    with app.test_client() as test_client, app.app_context():
        yield test_client


@pytest.fixture(scope="function")
def auth_client(app, admin_user):
    """
    Flask test client pre-authenticated as the admin user.

    Use this for testing protected routes that require login.
    The admin is logged in via the test login endpoint so Flask-Login
    sets a real session cookie.
    """
    with app.test_client() as test_client, app.app_context():
        # Simulate a login by posting to the auth endpoint
        test_client.post(
            "/auth/login",
            data={
                "username": admin_user.username,
                "password": "AdminTest@123",
            },
            follow_redirects=True,
        )
        yield test_client


# ==============================================================================
# USER FIXTURES
# ==============================================================================
@pytest.fixture(scope="function")
def admin_user(app, db_session):
    """
    Create and persist an admin user for the duration of one test.

    Password: AdminTest@123
    """
    from models.user import User

    user = User(
        username="test_admin",
        email="admin@test.local",
        role="admin",
        is_active=True,
        mfa_enabled=False,
    )
    user.set_password("AdminTest@123")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture(scope="function")
def analyst_user(app, db_session):
    """
    Create and persist an analyst user for the duration of one test.

    Password: AnalystTest@123
    """
    from models.user import User

    user = User(
        username="test_analyst",
        email="analyst@test.local",
        role="analyst",
        is_active=True,
        mfa_enabled=False,
    )
    user.set_password("AnalystTest@123")
    db_session.add(user)
    db_session.commit()
    return user


@pytest.fixture(scope="function")
def viewer_user(app, db_session):
    """
    Create and persist a viewer (read-only) user for the duration of one test.

    Password: ViewerTest@123
    """
    from models.user import User

    user = User(
        username="test_viewer",
        email="viewer@test.local",
        role="viewer",
        is_active=True,
        mfa_enabled=False,
    )
    user.set_password("ViewerTest@123")
    db_session.add(user)
    db_session.commit()
    return user


# ==============================================================================
# DATA FIXTURES
# ==============================================================================
@pytest.fixture(scope="function")
def sample_alert(app, db_session):
    """
    Create and persist one Alert row for use in alert-related tests.
    """
    from models.alert import Alert

    alert = Alert(
        threat_type=Alert.THREAT_PORT_SCAN,
        source_ip="192.168.1.100",
        severity=Alert.SEVERITY_HIGH,
        message="Port scan detected from 192.168.1.100: 25 unique ports in 10s.",
        time_detected=datetime.now(timezone.utc),
        acknowledged=False,
        resolved=False,
        false_positive=False,
    )
    db_session.add(alert)
    db_session.commit()
    return alert


@pytest.fixture(scope="function")
def sample_traffic_log(app, db_session):
    """
    Create and persist one TrafficLog row for use in log-related tests.
    """
    from models.traffic_log import TrafficLog

    log = TrafficLog(
        source_ip="10.0.0.5",
        destination_ip="10.0.0.1",
        protocol="TCP",
        port=80,
        packet_size=512,
        timestamp=datetime.now(timezone.utc),
        status=TrafficLog.STATUS_NORMAL,
        flags="S",
    )
    db_session.add(log)
    db_session.commit()
    return log


@pytest.fixture(scope="function")
def sample_rule(app, db_session):
    """
    Create and persist one DetectionRule row for use in rule-related tests.
    """
    from models.detection_rule import DetectionRule

    rule = DetectionRule(
        rule_name="Test Port Scan Rule",
        rule_type=DetectionRule.RULE_PORT_SCAN,
        description="Test rule for port scan detection.",
        threshold=20,
        window=10,
        severity="high",
        enabled=True,
    )
    db_session.add(rule)
    db_session.commit()
    return rule
