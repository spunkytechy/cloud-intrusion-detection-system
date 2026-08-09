"""
tests/test_models.py - Model Unit Tests
=========================================
Covers all four database models defined in Phase 2:

  TestUserModel          → models/user.py
  TestTrafficLogModel    → models/traffic_log.py
  TestAlertModel         → models/alert.py
  TestDetectionRuleModel → models/detection_rule.py
  TestAuditLogModel      → models/audit_log.py
  TestBaseModel          → shared save() / delete() / to_dict() on BaseModel
  TestDatabaseHelpers    → check_db_connection(), get_db_stats()

All tests run against an in-memory SQLite database (TestingConfig).
No real AWS RDS connection is required to run the test suite.

Run with:
    pytest tests/test_models.py -v
    pytest tests/test_models.py -v --tb=short
"""

from datetime import datetime, timedelta, timezone

import pytest


# ==============================================================================
# USER MODEL TESTS
# ==============================================================================
class TestUserModel:
    """Tests for models/user.py"""

    def test_user_creation(self, db_session):
        """A User can be created with required fields and saved."""
        from models.user import User

        user = User(
            username="jdoe",
            email="jdoe@example.com",
            role="analyst",
            is_active=True,
        )
        user.set_password("SecurePass@1")
        db_session.add(user)
        db_session.commit()

        assert user.id is not None
        assert user.username == "jdoe"
        assert user.email == "jdoe@example.com"
        assert user.role == "analyst"
        assert user.is_active is True

    def test_password_hashing(self, db_session):
        """Password is stored as a hash, not plain text."""
        from models.user import User

        user = User(username="hashtest", email="hash@test.com", role="viewer")
        user.set_password("PlainText@99")
        db_session.add(user)
        db_session.commit()

        # Hash must NOT equal the original password
        assert user.password_hash != "PlainText@99"
        # check_password must return True for the correct password
        assert user.check_password("PlainText@99") is True
        # check_password must return False for a wrong password
        assert user.check_password("WrongPass@99") is False

    def test_password_hash_is_never_serialised(self, admin_user):
        """to_dict() must never expose the password_hash field."""
        data = admin_user.to_dict()
        assert "password_hash" not in data

    def test_role_helpers(self, admin_user, analyst_user, viewer_user):
        """is_admin() and is_analyst() return correct booleans per role."""
        assert admin_user.is_admin() is True
        assert admin_user.is_analyst() is True  # admin is also an analyst

        assert analyst_user.is_admin() is False
        assert analyst_user.is_analyst() is True

        assert viewer_user.is_admin() is False
        assert viewer_user.is_analyst() is False

    def test_flask_login_get_id(self, admin_user):
        """get_id() returns the user PK as a string (Flask-Login requirement)."""
        result = admin_user.get_id()
        assert isinstance(result, str)
        assert result == str(admin_user.id)

    def test_failed_login_increments_counter(self, admin_user):
        """record_failed_login() increments login_attempts."""
        assert admin_user.login_attempts == 0
        admin_user.record_failed_login()
        assert admin_user.login_attempts == 1
        admin_user.record_failed_login()
        assert admin_user.login_attempts == 2

    def test_account_locks_after_max_attempts(self, admin_user):
        """Account becomes locked after MAX_FAILED_ATTEMPTS failures."""
        from models.user import User

        for _ in range(User.MAX_FAILED_ATTEMPTS):
            admin_user.record_failed_login()

        assert admin_user.is_locked is True
        assert admin_user.locked_until is not None
        assert admin_user.locked_until > datetime.now(timezone.utc)

    def test_successful_login_resets_counter(self, admin_user):
        """record_successful_login() clears failed counter and sets last_login."""
        admin_user.record_failed_login()
        admin_user.record_failed_login()

        admin_user.record_successful_login()

        assert admin_user.login_attempts == 0
        assert admin_user.locked_until is None
        assert admin_user.last_login is not None

    def test_lockout_expires_automatically(self, admin_user, db_session):
        """is_locked returns False once locked_until is in the past."""
        # Manually set an expired lock
        admin_user.locked_until = datetime.now(timezone.utc) - timedelta(minutes=1)
        admin_user.login_attempts = 5
        db_session.commit()

        # is_locked should auto-clear the expired lock and return False
        assert admin_user.is_locked is False
        assert admin_user.locked_until is None

    def test_totp_secret_generation(self, admin_user):
        """generate_totp_secret() returns a non-empty Base32 string."""
        secret = admin_user.generate_totp_secret()
        assert secret is not None
        assert len(secret) >= 16

    def test_totp_uri_generation(self, admin_user):
        """get_totp_uri() returns a valid otpauth:// string."""
        admin_user.generate_totp_secret()
        uri = admin_user.get_totp_uri(issuer="TestIDS")
        assert uri.startswith("otpauth://totp/")
        assert "TestIDS" in uri
        assert admin_user.email in uri

    def test_totp_verification(self, admin_user):
        """A freshly generated TOTP token verifies correctly."""
        import pyotp

        admin_user.generate_totp_secret()
        totp = pyotp.TOTP(admin_user.totp_secret)
        current_token = totp.now()

        assert admin_user.verify_totp(current_token) is True
        assert admin_user.verify_totp("000000") is False

    def test_username_uniqueness(self, db_session):
        """Two users with the same username raises an IntegrityError."""
        from sqlalchemy.exc import IntegrityError

        from models.user import User

        u1 = User(username="duplicate", email="u1@test.com", role="viewer")
        u1.set_password("Pass@1")
        db_session.add(u1)
        db_session.commit()

        u2 = User(username="duplicate", email="u2@test.com", role="viewer")
        u2.set_password("Pass@2")
        db_session.add(u2)

        with pytest.raises(IntegrityError):
            db_session.commit()

        db_session.rollback()

    def test_email_uniqueness(self, db_session):
        """Two users with the same email raises an IntegrityError."""
        from sqlalchemy.exc import IntegrityError

        from models.user import User

        u1 = User(username="user_a", email="same@test.com", role="viewer")
        u1.set_password("Pass@1")
        db_session.add(u1)
        db_session.commit()

        u2 = User(username="user_b", email="same@test.com", role="viewer")
        u2.set_password("Pass@2")
        db_session.add(u2)

        with pytest.raises(IntegrityError):
            db_session.commit()

        db_session.rollback()

    def test_to_dict_fields(self, admin_user):
        """to_dict() returns all expected safe fields."""
        data = admin_user.to_dict()
        expected_keys = {
            "id",
            "username",
            "email",
            "role",
            "is_active",
            "mfa_enabled",
            "last_login",
            "created_at",
            "updated_at",
        }
        assert expected_keys.issubset(data.keys())


# ==============================================================================
# TRAFFIC LOG MODEL TESTS
# ==============================================================================
class TestTrafficLogModel:
    """Tests for models/traffic_log.py"""

    def test_traffic_log_creation(self, db_session):
        """A TrafficLog can be created and persisted."""
        from models.traffic_log import TrafficLog

        log = TrafficLog(
            source_ip="172.16.0.1",
            destination_ip="172.16.0.2",
            protocol="UDP",
            port=53,
            packet_size=128,
            status=TrafficLog.STATUS_NORMAL,
        )
        db_session.add(log)
        db_session.commit()

        assert log.id is not None
        assert log.source_ip == "172.16.0.1"
        assert log.protocol == "UDP"
        assert log.port == 53
        assert log.status == "normal"

    def test_default_status_is_normal(self, db_session):
        """Default status is 'normal' when not explicitly set."""
        from models.traffic_log import TrafficLog

        log = TrafficLog(
            source_ip="1.1.1.1",
            destination_ip="8.8.8.8",
            protocol="TCP",
            packet_size=64,
        )
        db_session.add(log)
        db_session.commit()

        assert log.status == TrafficLog.STATUS_NORMAL

    def test_status_constants(self):
        """STATUS_* class constants have correct string values."""
        from models.traffic_log import TrafficLog

        assert TrafficLog.STATUS_NORMAL == "normal"
        assert TrafficLog.STATUS_SUSPICIOUS == "suspicious"
        assert TrafficLog.STATUS_BLOCKED == "blocked"

    def test_timestamp_auto_set(self, db_session):
        """timestamp is automatically set to a recent UTC datetime."""
        from models.traffic_log import TrafficLog

        before = datetime.now(timezone.utc)
        log = TrafficLog(
            source_ip="5.5.5.5",
            destination_ip="6.6.6.6",
            protocol="ICMP",
            packet_size=40,
        )
        db_session.add(log)
        db_session.commit()
        after = datetime.now(timezone.utc)

        assert log.timestamp is not None
        # Allow naive/aware comparison by normalising
        ts = log.timestamp
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        assert before <= ts <= after

    def test_get_recent(self, db_session):
        """get_recent() returns logs ordered newest first."""
        from models.traffic_log import TrafficLog

        for i in range(5):
            log = TrafficLog(
                source_ip=f"10.0.0.{i}",
                destination_ip="192.168.1.1",
                protocol="TCP",
                packet_size=100,
            )
            db_session.add(log)
        db_session.commit()

        recent = TrafficLog.get_recent(limit=3)
        assert len(recent) <= 3

    def test_to_dict_contains_required_fields(self, sample_traffic_log):
        """to_dict() includes source_ip, destination_ip, protocol, port, packet_size."""
        data = sample_traffic_log.to_dict()
        for key in (
            "id",
            "source_ip",
            "destination_ip",
            "protocol",
            "port",
            "packet_size",
            "status",
            "timestamp",
        ):
            assert key in data, f"Missing key: {key}"

    def test_ipv6_address_stored(self, db_session):
        """IPv6 addresses (up to 45 chars) are stored without truncation."""
        from models.traffic_log import TrafficLog

        ipv6 = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"
        log = TrafficLog(
            source_ip=ipv6,
            destination_ip="::1",
            protocol="TCP",
            packet_size=60,
        )
        db_session.add(log)
        db_session.commit()

        assert log.source_ip == ipv6


# ==============================================================================
# ALERT MODEL TESTS
# ==============================================================================
class TestAlertModel:
    """Tests for models/alert.py"""

    def test_alert_creation(self, db_session):
        """An Alert can be created with required fields."""
        from models.alert import Alert

        alert = Alert(
            threat_type=Alert.THREAT_DDOS,
            source_ip="203.0.113.5",
            severity=Alert.SEVERITY_CRITICAL,
            message="DDoS flood detected: 1200 packets/second.",
        )
        db_session.add(alert)
        db_session.commit()

        assert alert.alert_id is not None
        assert alert.threat_type == "ddos"
        assert alert.severity == "critical"
        assert alert.acknowledged is False
        assert alert.resolved is False
        assert alert.false_positive is False

    def test_severity_constants(self):
        """Severity class constants hold correct string values."""
        from models.alert import Alert

        assert Alert.SEVERITY_CRITICAL == "critical"
        assert Alert.SEVERITY_HIGH == "high"
        assert Alert.SEVERITY_MEDIUM == "medium"
        assert Alert.SEVERITY_LOW == "low"

    def test_threat_type_constants(self):
        """Threat type class constants hold correct string values."""
        from models.alert import Alert

        assert Alert.THREAT_PORT_SCAN == "port_scan"
        assert Alert.THREAT_BRUTE_FORCE == "brute_force"
        assert Alert.THREAT_DDOS == "ddos"
        assert Alert.THREAT_SUSPICIOUS == "suspicious_ip"
        assert Alert.THREAT_TRAFFIC_SPIKE == "traffic_spike"

    def test_acknowledge(self, sample_alert):
        """acknowledge() sets acknowledged=True, stores analyst name and timestamp."""
        sample_alert.acknowledge("analyst_jane")

        assert sample_alert.acknowledged is True
        assert sample_alert.acknowledged_by == "analyst_jane"
        assert sample_alert.acknowledged_at is not None

    def test_mark_resolved(self, sample_alert):
        """mark_resolved() sets resolved=True."""
        sample_alert.mark_resolved()
        assert sample_alert.resolved is True

    def test_mark_false_positive(self, sample_alert):
        """mark_false_positive() sets false_positive=True and also acknowledges."""
        sample_alert.mark_false_positive()

        assert sample_alert.false_positive is True
        assert sample_alert.acknowledged is True
        assert sample_alert.acknowledged_at is not None

    def test_severity_badge_class(self):
        """severity_badge_class returns the correct Bootstrap class string."""
        from models.alert import Alert

        a = Alert(
            threat_type="ddos",
            source_ip="1.1.1.1",
            severity="critical",
            message="test",
        )
        assert a.severity_badge_class == "badge bg-danger"

        a.severity = "high"
        assert a.severity_badge_class == "badge bg-warning text-dark"

        a.severity = "medium"
        assert a.severity_badge_class == "badge bg-info text-dark"

        a.severity = "low"
        assert a.severity_badge_class == "badge bg-secondary"

    def test_get_unacknowledged(self, db_session):
        """get_unacknowledged() returns only unacknowledged, non-false-positive alerts."""
        from models.alert import Alert

        # Unacknowledged
        a1 = Alert(
            threat_type="ddos", source_ip="1.1.1.1", severity="high", message="unack"
        )
        # Already acknowledged
        a2 = Alert(
            threat_type="ddos",
            source_ip="2.2.2.2",
            severity="low",
            message="ack",
            acknowledged=True,
        )
        db_session.add_all([a1, a2])
        db_session.commit()

        results = Alert.get_unacknowledged()
        ids = [r.alert_id for r in results]
        assert a1.alert_id in ids
        assert a2.alert_id not in ids

    def test_count_by_severity(self, db_session):
        """count_by_severity() returns a dict with severity → count mapping."""
        from models.alert import Alert

        db_session.add(
            Alert(
                threat_type="ddos",
                source_ip="1.1.1.1",
                severity="critical",
                message="c1",
            )
        )
        db_session.add(
            Alert(
                threat_type="ddos",
                source_ip="1.1.1.2",
                severity="critical",
                message="c2",
            )
        )
        db_session.add(
            Alert(
                threat_type="port_scan",
                source_ip="1.1.1.3",
                severity="high",
                message="h1",
            )
        )
        db_session.commit()

        counts = Alert.count_by_severity()
        assert counts.get("critical", 0) >= 2
        assert counts.get("high", 0) >= 1

    def test_time_detected_auto_set(self, db_session):
        """time_detected defaults to a recent UTC datetime."""
        from models.alert import Alert

        before = datetime.now(timezone.utc)
        alert = Alert(
            threat_type="ddos",
            source_ip="9.9.9.9",
            severity="low",
            message="time test",
        )
        db_session.add(alert)
        db_session.commit()
        after = datetime.now(timezone.utc)

        ts = alert.time_detected
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        assert before <= ts <= after


# ==============================================================================
# DETECTION RULE MODEL TESTS
# ==============================================================================
class TestDetectionRuleModel:
    """Tests for models/detection_rule.py"""

    def test_rule_creation(self, db_session):
        """A DetectionRule can be created and persisted."""
        from models.detection_rule import DetectionRule

        rule = DetectionRule(
            rule_name="Unique Brute Force Rule",
            rule_type=DetectionRule.RULE_BRUTE_FORCE,
            description="Test brute force rule.",
            threshold=5,
            window=60,
            severity="high",
            enabled=True,
        )
        db_session.add(rule)
        db_session.commit()

        assert rule.id is not None
        assert rule.rule_name == "Unique Brute Force Rule"
        assert rule.enabled is True
        assert rule.threshold == 5

    def test_rule_type_constants(self):
        """Rule type class constants hold correct string values."""
        from models.detection_rule import DetectionRule

        assert DetectionRule.RULE_PORT_SCAN == "port_scan"
        assert DetectionRule.RULE_BRUTE_FORCE == "brute_force"
        assert DetectionRule.RULE_DDOS == "ddos"
        assert DetectionRule.RULE_SUSPICIOUS_IP == "suspicious_ip"
        assert DetectionRule.RULE_TRAFFIC_SPIKE == "traffic_spike"

    def test_toggle_disables_rule(self, sample_rule):
        """toggle() flips enabled from True to False."""
        assert sample_rule.enabled is True
        new_state = sample_rule.toggle()
        assert new_state is False
        assert sample_rule.enabled is False

    def test_toggle_enables_rule(self, sample_rule):
        """toggle() flips enabled from False back to True."""
        sample_rule.enabled = False
        new_state = sample_rule.toggle()
        assert new_state is True
        assert sample_rule.enabled is True

    def test_get_enabled_rules(self, db_session):
        """get_enabled_rules() returns only enabled rules."""
        from models.detection_rule import DetectionRule

        r_on = DetectionRule(
            rule_name="On Rule", rule_type="ddos", threshold=100, window=1, enabled=True
        )
        r_off = DetectionRule(
            rule_name="Off Rule",
            rule_type="ddos",
            threshold=100,
            window=1,
            enabled=False,
        )
        db_session.add_all([r_on, r_off])
        db_session.commit()

        enabled = DetectionRule.get_enabled_rules()
        names = [r.rule_name for r in enabled]
        assert "On Rule" in names
        assert "Off Rule" not in names

    def test_get_by_type(self, db_session):
        """get_by_type() returns the matching rule or None."""
        from models.detection_rule import DetectionRule

        rule = DetectionRule(
            rule_name="Unique DDoS Rule",
            rule_type=DetectionRule.RULE_DDOS,
            threshold=1000,
            window=1,
        )
        db_session.add(rule)
        db_session.commit()

        found = DetectionRule.get_by_type(DetectionRule.RULE_DDOS)
        assert found is not None
        assert found.rule_type == "ddos"

        not_found = DetectionRule.get_by_type("nonexistent_type")
        assert not_found is None

    def test_rule_name_uniqueness(self, db_session, sample_rule):
        """Two rules with the same name raise an IntegrityError."""
        from sqlalchemy.exc import IntegrityError

        from models.detection_rule import DetectionRule

        duplicate = DetectionRule(
            rule_name=sample_rule.rule_name,  # same name
            rule_type=DetectionRule.RULE_DDOS,
            threshold=10,
            window=5,
        )
        db_session.add(duplicate)

        with pytest.raises(IntegrityError):
            db_session.commit()

        db_session.rollback()

    def test_to_dict_fields(self, sample_rule):
        """to_dict() includes all expected rule fields."""
        data = sample_rule.to_dict()
        for key in (
            "id",
            "rule_name",
            "rule_type",
            "threshold",
            "window",
            "enabled",
            "severity",
        ):
            assert key in data, f"Missing key: {key}"


# ==============================================================================
# AUDIT LOG MODEL TESTS
# ==============================================================================
class TestAuditLogModel:
    """Tests for models/audit_log.py"""

    def test_audit_log_creation_via_factory(self, app, db_session):
        """AuditLog.log() creates and persists an audit entry."""
        from models.audit_log import AuditLog

        with app.app_context():
            entry = AuditLog.log(
                action=AuditLog.ACTION_LOGIN,
                user_id=1,
                username="test_admin",
                ip_address="127.0.0.1",
                details={"method": "password"},
            )

        assert entry.id is not None
        assert entry.action == AuditLog.ACTION_LOGIN
        assert entry.username == "test_admin"

    def test_action_constants(self):
        """Key action constants are defined with correct string values."""
        from models.audit_log import AuditLog

        assert AuditLog.ACTION_LOGIN == "login"
        assert AuditLog.ACTION_LOGOUT == "logout"
        assert AuditLog.ACTION_LOGIN_FAILED == "login_failed"
        assert AuditLog.ACTION_RULE_UPDATED == "rule_updated"

    def test_get_details_parses_json(self, app, db_session):
        """get_details() correctly deserialises the JSON details field."""
        from models.audit_log import AuditLog

        with app.app_context():
            entry = AuditLog.log(
                action=AuditLog.ACTION_SYSTEM,
                details={"key": "value", "count": 42},
            )

        parsed = entry.get_details()
        assert parsed["key"] == "value"
        assert parsed["count"] == 42

    def test_get_details_returns_empty_dict_for_null(self, db_session):
        """get_details() returns {} when details is None."""
        from models.audit_log import AuditLog

        entry = AuditLog(action="login", timestamp=datetime.now(timezone.utc))
        db_session.add(entry)
        db_session.commit()

        assert entry.get_details() == {}

    def test_get_recent(self, app, db_session):
        """get_recent() returns up to limit entries ordered newest first."""
        from models.audit_log import AuditLog

        with app.app_context():
            for i in range(5):
                AuditLog.log(action="login", username=f"user_{i}")

        recent = AuditLog.get_recent(limit=3)
        assert len(recent) <= 3

    def test_get_failed_logins(self, app, db_session):
        """get_failed_logins() returns only ACTION_LOGIN_FAILED entries."""
        from models.audit_log import AuditLog

        with app.app_context():
            AuditLog.log(
                action=AuditLog.ACTION_LOGIN_FAILED,
                username="attacker",
                ip_address="5.5.5.5",
            )
            AuditLog.log(
                action=AuditLog.ACTION_LOGIN, username="legit", ip_address="6.6.6.6"
            )

        failures = AuditLog.get_failed_logins()
        for entry in failures:
            assert entry.action == AuditLog.ACTION_LOGIN_FAILED

    def test_audit_log_to_dict(self, app, db_session):
        """to_dict() returns all expected fields."""
        from models.audit_log import AuditLog

        with app.app_context():
            entry = AuditLog.log(
                action=AuditLog.ACTION_LOGIN,
                username="test_admin",
                ip_address="127.0.0.1",
            )

        data = entry.to_dict()
        for key in (
            "id",
            "user_id",
            "username",
            "action",
            "target",
            "ip_address",
            "details",
            "timestamp",
        ):
            assert key in data, f"Missing key: {key}"


# ==============================================================================
# BASE MODEL TESTS
# ==============================================================================
class TestBaseModel:
    """Tests for shared BaseModel methods (save, delete, to_dict, count)."""

    def test_save_persists_record(self, db_session):
        """save() adds and commits a record to the database."""
        from models.traffic_log import TrafficLog

        log = TrafficLog(
            source_ip="10.1.1.1",
            destination_ip="10.1.1.2",
            protocol="TCP",
            packet_size=256,
        )
        log.save()
        assert log.id is not None

    def test_delete_removes_record(self, db_session):
        """delete() removes the record from the database."""
        from models.traffic_log import TrafficLog

        log = TrafficLog(
            source_ip="10.2.2.2",
            destination_ip="10.2.2.3",
            protocol="UDP",
            packet_size=64,
        )
        db_session.add(log)
        db_session.commit()
        log_id = log.id

        log.delete()
        assert TrafficLog.query.get(log_id) is None

    def test_get_by_id(self, sample_traffic_log):
        """get_by_id() retrieves a record by its primary key."""
        from models.traffic_log import TrafficLog

        found = TrafficLog.get_by_id(sample_traffic_log.id)
        assert found is not None
        assert found.id == sample_traffic_log.id

    def test_get_by_id_returns_none_for_missing(self, app):
        """get_by_id() returns None for a non-existent primary key."""
        from models.traffic_log import TrafficLog

        with app.app_context():
            result = TrafficLog.get_by_id(999999)
        assert result is None

    def test_count(self, db_session):
        """count() returns the correct number of rows."""
        from models.traffic_log import TrafficLog

        before = TrafficLog.count()
        db_session.add(
            TrafficLog(
                source_ip="99.99.99.99",
                destination_ip="88.88.88.88",
                protocol="TCP",
                packet_size=100,
            )
        )
        db_session.commit()
        assert TrafficLog.count() == before + 1


# ==============================================================================
# DATABASE HELPER TESTS
# ==============================================================================
class TestDatabaseHelpers:
    """Tests for database/db.py health check and stats helpers."""

    def test_check_db_connection_returns_ok(self, app):
        """check_db_connection() returns status='ok' with a valid DB."""
        from database.db import check_db_connection

        with app.app_context():
            result = check_db_connection()

        assert result["status"] == "ok"
        assert result["latency_ms"] is not None
        assert isinstance(result["latency_ms"], float)

    def test_get_db_stats_returns_dict(self, app):
        """get_db_stats() returns a dict with all expected table keys."""
        from database.db import get_db_stats

        with app.app_context():
            stats = get_db_stats()

        expected_keys = {
            "users",
            "traffic_logs",
            "alerts",
            "detection_rules",
            "audit_logs",
        }
        assert expected_keys.issubset(stats.keys())

    def test_get_db_stats_values_are_integers(self, app):
        """Each value returned by get_db_stats() is an integer."""
        from database.db import get_db_stats

        with app.app_context():
            stats = get_db_stats()

        for table, count in stats.items():
            assert isinstance(
                count, int
            ), f"Expected int for '{table}', got {type(count)}"
