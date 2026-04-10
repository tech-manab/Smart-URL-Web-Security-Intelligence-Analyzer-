# 🔗 Smart URL Status Checker & Website Health Analyzer
# 🛡️ Now with **Wazuh Security Monitoring** & SOC Dashboard!

A professional college project — a mini website monitoring tool + **Security Operations Center Dashboard** built with **Python Flask** + **SQLite** + **HTML/CSS/JS**.

**✨ UPGRADE ALERT**: This project now includes advanced security intelligence with Wazuh integration! See [UPGRADE_GUIDE.md](UPGRADE_GUIDE.md) for new features.

---

## 🆕 What's New!

### 🎯 Mini SOC Dashboard
- **Real-Time Threat Monitoring** - Live security alerts feed
- **Risk Classification** - CRITICAL, HIGH, MEDIUM, LOW, INFO
- **Security Scoring Engine** - 0-100 intelligent score calculation
- **Wazuh Integration** - Structured logging for security operations

### 🔐 Enhanced Security Features
- **10+ Alert Rules** - Automated threat detection
- **Security Headers Analysis** - CSP, HSTS, X-Frame-Options checking
- **SSL/TLS Validation** - Certificate and encryption verification
- **Suspicious Domain Detection** - Phishing pattern recognition
- **Performance Analysis** - Latency and response time assessment

### 🎨 Modern UI/UX
- **Glassmorphism Design** - Beautiful modern glass panels
- **Animated Charts** - Interactive visualization with Chart.js
- **Real-Time Dashboards** - Live updates every 5 seconds
- **Risk Badges** - Color-coded threat severity indicators
- **Smooth Animations** - Professional effects and transitions

### 📡 New API Endpoints
```
GET  /api/wazuh/alerts           - Security alerts
GET  /api/wazuh/alerts/stats     - Alert statistics
GET  /api/security/dashboard     - SOC dashboard data
GET  /api/security/score/<url>   - URL security analysis
GET  /api/monitoring/live        - Real-time activity
```

---

## 📁 Project Structure

```
smart_url_checker/
├── app.py                          # Flask backend (enhanced with Wazuh)
├── requirements.txt                # Python dependencies
├── url_checker.db                  # SQLite database
├── README.md                       # This file
├── UPGRADE_GUIDE.md               # 🆕 Wazuh upgrade instructions
├── WAZUH_INTEGRATION.md           # 🆕 Integration documentation
├── logs/
│   └── url_scan.log               # 🆕 Wazuh-compatible JSON logs
├── static/
│   ├── css/
│   │   └── style.css              # Enhanced styling + glassmorphism
│   └── js/
│       ├── script.js              # Main frontend logic
│       ├── wazuh-dashboard.js     # 🆕 SOC dashboard controller
│       └── soc-patches.js         # 🆕 Integration patches
└── templates/
    ├── index.html                 # Enhanced UI with SOC dashboard
    ├── admin.html                 # Admin panel
    └── login.html                 # User authentication
```

---

## ⚙️ Setup & Run

### 1. Install Python (3.9+)
Make sure Python and pip are installed:
```bash
python --version
pip --version
```

### 2. (Optional) Create a Virtual Environment
```bash
python -m venv venv
# Windows:
venv\Scripts\activate
# Mac/Linux:
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the App
```bash
python app.py
```

### 5. Open in Browser
Visit: **http://127.0.0.1:5000**

---

## ✨ Features

| Feature | Details |
|---|---|
| Single URL Check | Enter any URL and get a full health report |
| Bulk URL Check | Check up to 20 URLs at once |
| HTTP Status Code | Displays 200, 301, 404, 500, etc. |
| Response Time | Measured in milliseconds |
| SSL Detection | Shows 🔒 HTTPS or ⚠️ HTTP |
| Redirect Detection | Original → Final URL + redirect count |
| Health Status | Up / Slow / Down / Redirected / Broken |
| Availability Score | Excellent / Good / Average / Poor |
| Check History | SQLite-stored, last 100 entries |
| Export CSV | Download history as spreadsheet |
| Export PDF | Download styled PDF report (requires reportlab) |
| Recheck Button | Re-test any URL instantly |
| Dark / Light Mode | Toggle with memory (localStorage) |
| Responsive | Works on laptop and mobile |
| Error Handling | Invalid URL, timeout, DNS, SSL errors |

---

## 🎨 Tech Stack

- **Backend**: Python 3, Flask, requests, sqlite3, csv, io
- **PDF Export**: reportlab
- **Frontend**: HTML5, CSS3, Vanilla JavaScript
- **Database**: SQLite (no external DB needed)
- **Fonts**: Oxanium (display) + DM Sans (body) — Google Fonts

---

## 🖥️ Interface Sections

1. **Hero Dashboard** — Stats cards (Total / Up / Down / Slow)
2. **Single Check Tab** — One URL analysis with full result card
3. **Bulk Check Tab** — Multi-URL checker with summary
4. **History Tab** — Table of past checks + CSV/PDF export

---

## 📝 Notes

- The SQLite database file `url_checker.db` is created automatically on first run.
- PDF export requires `reportlab` (included in requirements.txt).
- URLs without `http://` or `https://` are automatically prefixed with `https://`.
- Maximum 20 URLs per bulk check request.

---

## 👨‍💻 College Project

**Title**: Smart URL Status Checker and Website Health Analyzer  
**Tech**: Python Flask · SQLite · HTML · CSS · JavaScript  
**Purpose**: Demonstrate web monitoring, HTTP analysis, and full-stack development skills.
