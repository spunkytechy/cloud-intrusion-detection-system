# DESIGN AND IMPLEMENTATION OF A CLOUD INTRUSION DETECTION SYSTEM (IDS)

A production-ready, real-time Cloud Intrusion Detection System (IDS) built with Python 3.12, Flask, Flask-SocketIO, Scapy, PostgreSQL, Docker, and AWS EC2/RDS.

---

## 📋 System Architecture

```
                               ┌─────────────────────────┐
                               │   Network Traffic       │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │ Packet Capture (Scapy)  │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │    Detection Engine     │
                               │ - Port Scan (20/10s)    │
                               │ - Brute Force (5 fail)  │
                               │ - DDoS (1000/s)         │
                               │ - Suspicious IP / Spike │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │   Alert Generator       │
                               │ (Critical/High/Med/Low) │
                               └────────────┬────────────┘
                                            │
                    ┌───────────────────────┴───────────────────────┐
                    ▼                                               ▼
     ┌─────────────────────────────┐                 ┌─────────────────────────────┐
     │  Real-Time WebSocket /ids   │                 │   Database (PostgreSQL)     │
     │   (Flask-SocketIO / Chart)  │                 │ (Logs, Alerts, Rules, User) │
     └─────────────────────────────┘                 └─────────────────────────────┘
```

---

## 🚀 Features

- **Real-Time Packet Capture**: Powered by Scapy packet sniffer and threaded queue analyzer.
- **Rule-Based Threat Detection Engine**:
  - **Port Scanning**: Detects >20 port requests from a single IP within 10 seconds.
  - **Brute Force Attacks**: Detects >5 failed authentication attempts within 60 seconds.
  - **DDoS Attacks**: Detects >1,000 packets per second.
  - **Suspicious IP Activity**: Identifies traffic from blacklisted/reputation-flagged IPs.
  - **Traffic Anomaly / Spike Detection**: Flags volumetric anomalies exceeding baseline thresholds.
- **Real-Time Dashboard**: Interactive dark-mode dashboard powered by Bootstrap 5, Chart.js, and Flask-SocketIO.
- **Authentication & Security**: Role-Based Access Control (Admin / Analyst / Viewer), bcrypt password hashing, CSRF protection, rate limiting, and Audit Logging.
- **REST & JWT API**: Endpoints for `/api/v1/health`, `/api/v1/stats`, `/api/v1/alerts/recent`, `/api/v1/traffic/recent`.
- **Export & Reporting**: CSV log and alert exporting.
- **Containerization & Deployment**: Dockerized multi-container setup (Flask + Gunicorn + Nginx + PostgreSQL) with AWS EC2 & RDS deployment guide.

---

## 📁 Directory Structure

```text
cloud_ids/
│
├── app.py                  # Application Factory Pattern & Extensions
├── config.py               # Development, Testing & Production Configs
├── requirements.txt        # Python Dependencies
├── docker-compose.yml      # Multi-container Orchestration
├── Dockerfile              # Flask / Gunicorn Container Specification
├── nginx.conf              # Reverse Proxy Configuration
├── .env                    # Environment Configuration File
├── README.md               # System Documentation & Guide
│
├── models/                 # SQLAlchemy Models (User, TrafficLog, Alert, DetectionRule, AuditLog)
├── routes/                 # Flask Blueprints (Auth, Dashboard, Alerts, Logs, Rules, API)
├── packet_capture/         # Scapy Packet Sniffer & Packet Analyzer
├── detection/              # Rule Engine & Threat Classifier
├── alerts/                 # Alert Generator & Email / SocketIO Dispatcher
├── auth/                   # RBAC Decorators & Security Utilities
├── database/               # Shared SQLAlchemy Instance & Seeder
├── templates/              # Jinja2 Templates (Dark Mode Bootstrap Dashboard & Forms)
├── static/                 # CSS Stylesheets & JavaScript
├── logs/                   # System Log Files
└── tests/                  # Automated Test Suite & Flow Verification
```

---

## 🛠️ Local Development Setup (Windows 11 / Linux)

### 1. Prerequisites
- Python 3.12+
- PostgreSQL (or local SQLite fallback)
- Npcap (for Windows raw packet capture with Scapy: https://npcap.com)

### 2. Setup Virtual Environment
```powershell
cd cloud_ids
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### 3. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 4. Configure Environment
Copy `.env.example` to `.env` and adjust configuration settings as needed:
```powershell
cp .env.example .env
```

### 5. Run the Application
```powershell
python app.py
```
Open browser at: `http://localhost:5000`

---

## 🐳 Docker Deployment

To build and run all containers (Flask App + Gunicorn, Nginx Proxy, PostgreSQL Database):

```bash
docker compose up --build -d
```

Verify running containers:
```bash
docker compose ps
```

Stop containers:
```bash
docker compose down
```

---

## ☁️ AWS Cloud Deployment (EC2 + RDS)

1. **Launch RDS PostgreSQL Instance**:
   - Engine: PostgreSQL 15+
   - Security Group: Allow inbound 5432 from EC2 Security Group.

2. **Launch EC2 Instance (Ubuntu 22.04 LTS)**:
   - Security Group: Allow TCP ports 80, 443, 22.

3. **Install Docker & Docker Compose on EC2**:
   ```bash
   sudo apt update && sudo apt install -y docker.io docker-compose-v2
   sudo systemctl enable --now docker
   ```

4. **Clone Repository & Configure `.env`**:
   ```bash
   git clone <your-repo-url> cloud_ids
   cd cloud_ids
   cp .env.example .env
   # Update DATABASE_URL with RDS endpoint
   ```

5. **Start Production Stack**:
   ```bash
   docker compose up --build -d
   ```

---

## 🛡️ Verification & Security Testing

Run the automated integration test suite:
```powershell
python tests/test_full_flow.py
```

### Simulated Security Tests (Nmap / Hydra / Hping3):

1. **Port Scan Simulation (Nmap)**:
   ```bash
   nmap -sS -p 1-100 <TARGET_IP>
   ```
2. **Brute Force Simulation (Hydra)**:
   ```bash
   hydra -l admin -P passwords.txt <TARGET_IP> http-post-form "/auth/login:username=^USER^&password=^PASS^:Invalid"
   ```
3. **DDoS Traffic Simulation (Hping3)**:
   ```bash
   sudo hping3 --flood --rand-source -p 80 <TARGET_IP>
   ```

---

## 📜 License & Citation

Design and Implementation of a Cloud Intrusion Detection System (IDS).
Production-ready cybersecurity application codebase.
