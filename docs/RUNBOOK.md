# CyberGuard AI - Operational Runbook & SOC Guide

This runbook provides deployment, operations, monitoring, and troubleshooting instructions for SecOps engineers operating CyberGuard AI.

---

## 1. Quick Deployment

### Option A: Local Python Environment
```bash
# Clone the repository
git clone https://github.com/abhi-302-e/CyberGuard-AI.git
cd CyberGuard-AI

# Install dependencies
pip install -r requirements.txt

# Run simulation test suite
python run_simulation.py storm_2603

# Launch SOC Command Dashboard
python -m cyberguard.ui.dashboard
# Open http://localhost:5000 in your browser
```

### Option B: Docker Container
```bash
docker-compose up --build -d
```
Access the dashboard at `http://localhost:5000` and REST API at `http://localhost:8080/api/v1`.

---

## 2. Operational Procedures

### Simulating Attack Scenarios
You can trigger pre-built scenarios from the CLI or dashboard:
1. **Storm-2603 SharePoint ToolShell:** `python run_simulation.py storm_2603`
2. **OpenSSH SSHole Bypass:** `python run_simulation.py sshole`
3. **Dharma / Has Ransomware:** `python run_simulation.py has_ransomware`
4. **Rogue AI Security Agent:** `python run_simulation.py rogue_ai`
5. **Benign Baseline:** `python run_simulation.py benign`

### Ingesting Real Telemetry via REST API
```bash
curl -X POST http://localhost:8080/api/v1/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "source": "FIREWALL",
        "src_ip": "194.26.29.112",
        "dst_ip": "10.0.1.20",
        "dst_port": 22,
        "action": "AUTH_FAILED",
        "message": "Failed password for root",
        "metadata": {"failed_attempts": 5}
      }
    ]
  }'
```

### Monitoring System Performance & Metrics
```bash
curl http://localhost:5000/api/metrics
```

### Reviewing Gated Incidents
When an action targets a critical Tier-0 asset (e.g. Active Directory Domain Controller `10.0.0.1`), CyberGuard AI gates the containment action and marks `status: AWAITING_HUMAN_APPROVAL`.
The incident commander reviews the ticket in Jira and executes sign-off via the API.
