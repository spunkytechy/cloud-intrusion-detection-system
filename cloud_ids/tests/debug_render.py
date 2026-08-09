"""Debug: check what the dashboard actually renders after login."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from config import TestingConfig
from database.db import db as _db

app = create_app(TestingConfig)
with app.app_context():
    _db.create_all()

with app.test_client() as c:
    c.post('/auth/register', data={
        'username': 'debuguser', 'email': 'd@d.com',
        'password': 'Debug@123', 'confirm_password': 'Debug@123'
    })
    c.post('/auth/login', data={'username': 'debuguser', 'password': 'Debug@123'})

    r = c.get('/dashboard/', follow_redirects=True)
    html = r.data.decode('utf-8')

    print("Status:", r.status_code)
    print("Has sidebar:", 'id="sidebar"' in html)
    print("Has main-content div:", 'id="main-content"' in html)
    print("Has stat-packets:", 'stat-packets' in html)
    print("Has Total Packets text:", 'Total Packets' in html)
    print("Has block content:", 'bi-speedometer2' in html)
    print("HTML length:", len(html))

    # Print around the main-content div
    idx = html.find('id="main-content"')
    if idx >= 0:
        print("\n--- main-content area (first 600 chars) ---")
        print(html[idx:idx+600])
    else:
        print("\nmain-content div NOT FOUND in output")
        print("\n--- First 1000 chars of body ---")
        body_start = html.find('<body>')
        print(html[body_start:body_start+1000] if body_start >= 0 else html[:1000])
