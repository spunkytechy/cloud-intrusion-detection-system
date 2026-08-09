"""Quick end-to-end verification script."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from config import TestingConfig
from database.db import db as _db

app = create_app(TestingConfig)

with app.app_context():
    _db.create_all()

failures = []

with app.test_client() as client:
    # Register
    r = client.post('/auth/register', data={
        'username': 'flowtest', 'email': 'flow@test.com',
        'password': 'FlowTest@1', 'confirm_password': 'FlowTest@1'
    }, follow_redirects=False)
    status = "OK" if r.status_code == 302 else "ERR"
    if status == "ERR": failures.append("register")
    print(f"  {status}  Register           -> {r.status_code}")

    # Login
    r = client.post('/auth/login', data={
        'username': 'flowtest', 'password': 'FlowTest@1'
    }, follow_redirects=False)
    status = "OK" if r.status_code == 302 else "ERR"
    if status == "ERR": failures.append("login")
    print(f"  {status}  Login              -> {r.status_code}")

    # Protected pages (must be 200 after login)
    pages = [
        ('/dashboard/',        'Dashboard'),
        ('/alerts/',           'Alerts'),
        ('/logs/',             'Traffic Logs'),
        ('/rules/',            'Rules'),
        ('/dashboard/stats',   'Statistics'),
        ('/dashboard/settings','Settings (admin)'),
        ('/api/v1/health',     'Health API'),
        ('/api/v1/stats',      'Stats API'),
    ]
    for path, label in pages:
        r = client.get(path, follow_redirects=True)
        status = "OK" if r.status_code == 200 else "ERR"
        if status == "ERR": failures.append(label)
        print(f"  {status}  {label:22s} -> {r.status_code}")

    # Logout
    r = client.get('/auth/logout', follow_redirects=False)
    status = "OK" if r.status_code == 302 else "ERR"
    if status == "ERR": failures.append("logout")
    print(f"  {status}  Logout             -> {r.status_code}")

    # After logout, protected page must redirect to login
    r = client.get('/dashboard/', follow_redirects=False)
    status = "OK" if r.status_code == 302 else "ERR"
    if status == "ERR": failures.append("post-logout redirect")
    print(f"  {status}  Post-logout guard  -> {r.status_code}")

print()
if failures:
    print("FAILED:", failures)
    sys.exit(1)
else:
    print("ALL CHECKS PASSED")
