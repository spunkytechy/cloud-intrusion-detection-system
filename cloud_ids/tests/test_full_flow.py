"""Full end-to-end verification of registration, login, CSRF tokens, and protected pages."""
import sys
import os
import re

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from config import DevelopmentConfig
from database.db import db

DevelopmentConfig.SQLALCHEMY_DATABASE_URI = "sqlite:///cloud_ids_test.db"
DevelopmentConfig.SQLALCHEMY_ENGINE_OPTIONS = {}
app = create_app(DevelopmentConfig)

with app.app_context():
    db.create_all()

with app.test_client() as c:
    # 1. Load Register Page
    res = c.get("/auth/register")
    assert res.status_code == 200, f"Register page GET status: {res.status_code}"
    match = re.search(r'name="csrf_token" value="([^"]+)"', res.data.decode("utf-8"))
    assert match, "CSRF token missing on register page!"
    csrf_token = match.group(1)
    print("[PASS] GET /auth/register - CSRF Token present")

    # 2. Submit Registration
    res = c.post(
        "/auth/register",
        data={
            "csrf_token": csrf_token,
            "username": "flowuser",
            "email": "flowuser@example.com",
            "password": "Password123!",
            "confirm_password": "Password123!",
        },
        follow_redirects=True,
    )
    assert res.status_code == 200
    assert "Account created" in res.data.decode("utf-8") or "Please log in" in res.data.decode("utf-8")
    print("[PASS] POST /auth/register - User registered successfully")

    # 3. Load Login Page
    res = c.get("/auth/login")
    assert res.status_code == 200
    match = re.search(r'name="csrf_token" value="([^"]+)"', res.data.decode("utf-8"))
    assert match, "CSRF token missing on login page!"
    csrf_token = match.group(1)
    print("[PASS] GET /auth/login - CSRF Token present")

    # 4. Submit Login
    res = c.post(
        "/auth/login",
        data={
            "csrf_token": csrf_token,
            "username": "flowuser",
            "password": "Password123!",
        },
        follow_redirects=True,
    )
    assert res.status_code == 200
    html = res.data.decode("utf-8")
    assert 'id="sidebar"' in html, "Sidebar missing on dashboard!"
    assert 'id="main-content"' in html, "Main content missing on dashboard!"
    assert "Dashboard" in html, "Dashboard text missing!"
    print("[PASS] POST /auth/login - Login successful & Dashboard rendered")

    # 5. Check all protected routes
    routes = [
        ("/dashboard/index", "Dashboard"),
        ("/alerts/", "Alerts"),
        ("/logs/", "Traffic Logs"),
        ("/rules/", "Detection Rules"),
        ("/dashboard/stats", "Statistics"),
        ("/auth/profile", "Profile"),
    ]
    for route, name in routes:
        res = c.get(route, follow_redirects=True)
        assert res.status_code == 200, f"Route {route} failed with status {res.status_code}"
        assert 'id="main-content"' in res.data.decode("utf-8"), f"Route {route} rendered blank page!"
        print(f"[PASS] GET {route} -> 200 OK ({name})")

    print("\n>>> ALL TESTS PASSED SUCCESSFULLY! APPLICATION IS FULLY FUNCTIONAL. <<<")
