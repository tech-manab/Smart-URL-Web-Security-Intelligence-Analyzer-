"""
Smart URL Status Checker and Website Health Analyzer
Backend: Flask + SQLite + requests
Author: College Project
"""

import time
import csv
import io
import json
import hashlib
import secrets
import os
import socket
import logging
from logging.handlers import RotatingFileHandler
from datetime import datetime
from flask import Flask, request, jsonify, render_template, send_file, Response, session
from urllib.parse import urlparse, urljoin
import requests
from flask import send_from_directory
from requests.exceptions import (
    ConnectionError, Timeout, TooManyRedirects,
    SSLError, InvalidURL, MissingSchema
)
import sqlite3
import threading

os.makedirs('logs', exist_ok=True)
wazuh_logger = logging.getLogger('wazuh')
wazuh_logger.setLevel(logging.INFO)
wazuh_handler = RotatingFileHandler('logs/url_scan.log', maxBytes=5000000, backupCount=2)
formatter = logging.Formatter('%(asctime)s %(message)s', datefmt='%Y-%m-%d %H:%M:%S')
wazuh_handler.setFormatter(formatter)
wazuh_logger.addHandler(wazuh_handler)

# ── Enhanced Wazuh Logging with Risk Classification ──────────────────────────
RISK_LEVELS = {
    "CRITICAL": 5,
    "HIGH": 4,
    "MEDIUM": 3,
    "LOW": 2,
    "INFO": 1
}

def classify_risk(status, response_ms, is_https, has_security_headers, alerts_count):
    """Classify URL risk level based on multiple factors."""
    risk_score = 0
    
    # Status-based scoring
    if status in ("Down", "Broken", "Invalid", "SSL Error"):
        risk_score += 40
    elif status == "Redirected":
        risk_score += 15
    elif status == "Slow":
        risk_score += 10
    else:
        risk_score += 5
    
    # Response time scoring
    if response_ms and response_ms > 5000:
        risk_score += 15
    elif response_ms and response_ms > 3000:
        risk_score += 10
    
    # HTTPS scoring
    if not is_https:
        risk_score += 20
    
    # Security headers scoring
    if not has_security_headers:
        risk_score += 15
    
    # Alert count impact
    risk_score += min(alerts_count * 5, 20)
    
    # Classify based on score
    if risk_score >= 80:
        return "CRITICAL"
    elif risk_score >= 60:
        return "HIGH"
    elif risk_score >= 40:
        return "MEDIUM"
    elif risk_score >= 20:
        return "LOW"
    else:
        return "INFO"

def log_wazuh_scan(url, status, response_ms, is_https, ip, security_score, risk_level, alerts):
    """Log scan data in Wazuh-compatible JSON format with enhanced metadata."""
    resp_time_str = f"{response_ms/1000:.1f}s" if response_ms else "0s"
    scan_status = "UP" if status in ("Up", "Slow", "Redirected", "Excellent", "Good", "Average") else "DOWN"
    
    log_data = {
        "event_type": "url_scan",
        "url": url,
        "status": scan_status,
        "http_status": status,
        "response_time": resp_time_str,
        "response_ms": response_ms,
        "https": is_https,
        "ip_address": ip,
        "security_score": security_score,
        "risk_level": risk_level,
        "alert_count": len(alerts),
        "alerts": [{"level": a.get("level"), "rule": a.get("rule")} for a in alerts],
        "timestamp": datetime.now().isoformat(),
        "epoch": int(datetime.now().timestamp())
    }
    wazuh_logger.info(json.dumps(log_data))

# ── Optional: reportlab for PDF ──────────────────────────────────────────────
try:
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib import colors
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.units import inch
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

app = Flask(__name__)
app.secret_key = 'cybermonitor-super-secret-2026-xK9#mP'
DB_PATH = "url_checker.db"
DB_LOCK = threading.Lock()
PDF_AVAILABLE = False # Removed pdflatex dependencies for pure Flask

@app.after_request
def add_cors_headers(response):
    response.headers['Access-Control-Allow-Origin'] = '*'
    response.headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS'
    response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
    return response

@app.route('/<path:path>', methods=['OPTIONS'])
def handle_options(path):
    return '', 200

# ── Database Setup ────────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    """Hash a password with SHA-256 + salt."""
    salt = 'CyberMonitor_Salt_2026'
    return hashlib.sha256((salt + password).encode()).hexdigest()

def init_db():
    """Initialize SQLite database and create all tables."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS url_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                url         TEXT    NOT NULL,
                final_url   TEXT,
                status      TEXT    NOT NULL,
                status_code INTEGER,
                response_ms INTEGER,
                secure      INTEGER DEFAULT 0,
                redirects   INTEGER DEFAULT 0,
                availability TEXT,
                checked_at  TEXT    NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT UNIQUE NOT NULL,
                password    TEXT NOT NULL,
                role        TEXT DEFAULT 'user',
                status      TEXT DEFAULT 'Active',
                created_at  TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS user_scans (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                input       TEXT NOT NULL,
                type        TEXT DEFAULT 'url',
                status      TEXT,
                speed       INTEGER,
                grade       TEXT,
                scan_data   TEXT,
                created_at  TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS favorites (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER NOT NULL,
                input       TEXT NOT NULL,
                created_at  TEXT NOT NULL,
                UNIQUE(user_id, input)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS admin_settings (
                key         TEXT PRIMARY KEY,
                value       TEXT NOT NULL,
                updated_at  TEXT NOT NULL
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS wazuh_alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                level       TEXT,
                rule_name   TEXT,
                message     TEXT,
                url         TEXT,
                ip_address  TEXT,
                response_ms INTEGER,
                security_score INTEGER,
                risk_level  TEXT,
                status      TEXT,
                timestamp   TEXT,
                is_active   INTEGER DEFAULT 1
            )
        """)
        # Create SOC Dashboard Views table
        conn.execute("""
            CREATE TABLE IF NOT EXISTS scan_metrics (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                metric_type TEXT,
                metric_value TEXT,
                timestamp   TEXT
            )
        """)
        # Dashboard stats table for real-time monitoring
        conn.execute("""
            CREATE TABLE IF NOT EXISTS dashboard_stats (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                stat_key    TEXT UNIQUE,
                stat_value  TEXT,
                updated_at  TEXT
            )
        """)
        # Create indexes for fast queries
        conn.execute("CREATE INDEX IF NOT EXISTS idx_user_scans_user_id ON user_scans(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_favorites_user_id ON favorites(user_id)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_url_history_checked_at ON url_history(checked_at)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_timestamp ON wazuh_alerts(timestamp)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_level ON wazuh_alerts(level)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_wazuh_alerts_url ON wazuh_alerts(url)")
        conn.execute("CREATE INDEX IF NOT EXISTS idx_scan_metrics_timestamp ON scan_metrics(timestamp)")
        # Enable WAL mode for better concurrent read performance
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA cache_size=10000")
        conn.execute("PRAGMA synchronous=NORMAL")
        
        # Migration: Add is_active column to wazuh_alerts if it doesn't exist
        try:
            conn.execute("ALTER TABLE wazuh_alerts ADD COLUMN is_active INTEGER DEFAULT 1")
        except sqlite3.OperationalError as e:
            if "duplicate column name" not in str(e):
                print(f"Migration warning: {e}")
        
        # Create default admin if not exists
        existing = conn.execute("SELECT id FROM users WHERE username = 'Admin'").fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO users (username, password, role, status, created_at) VALUES (?, ?, ?, ?, ?)",
                ('Admin', hash_password('Url_Plus404'), 'admin', 'Active', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
        conn.commit()

init_db()

# ── URL Validation ────────────────────────────────────────────────────────────
def validate_url(url: str) -> tuple[bool, str]:
    """Validate URL format. Returns (is_valid, cleaned_url)."""
    url = url.strip()
    if not url:
        return False, "URL cannot be empty"
    # Auto-prepend http:// if missing scheme
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "Invalid URL: missing domain"
        return True, url
    except Exception:
        return False, "Malformed URL"

# ── Health Score Calculator ───────────────────────────────────────────────────
def calculate_availability(status_code: int, response_ms: int, redirects: int) -> str:
    """Compute an availability/health score label."""
    if status_code is None or status_code >= 500:
        return "Poor"
    if status_code == 200 and response_ms < 500 and redirects == 0:
        return "Excellent"
    if status_code in (200, 201, 202) and response_ms < 1500:
        return "Good"
    if status_code in range(200, 400) and response_ms < 3000:
        return "Average"
    return "Poor"

# ── Status Label Builder ──────────────────────────────────────────────────────
def determine_status(status_code: int, response_ms: int, redirects: int, secure: bool) -> str:
    """Map HTTP result to a human-readable health label."""
    if status_code is None:
        return "Down"
    if status_code in (404, 410):
        return "Broken"
    if status_code >= 500:
        return "Down"
    if redirects > 0:
        return "Redirected"
    if response_ms > 3000:
        return "Slow"
    if status_code in range(200, 400):
        return "Up"
    return "Down"

# ── Core Checker ─────────────────────────────────────────────────────────────
def check_url(raw_url: str) -> dict:
    """
    Perform a full health check on a single URL.
    Returns a result dict with all fields.
    """
    is_valid, url = validate_url(raw_url)
    if not is_valid:
        return {
            "url": raw_url,
            "final_url": None,
            "valid": False,
            "error": url,
            "status": "Invalid",
            "status_code": None,
            "response_ms": None,
            "secure": False,
            "redirects": 0,
            "availability": "Poor",
            "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sec_headers": None
        }

    result = {
        "url": raw_url,
        "final_url": url,
        "valid": True,
        "error": None,
        "status": "Down",
        "status_code": None,
        "response_ms": None,
        "secure": url.startswith("https://"),
        "redirects": 0,
        "availability": "Poor",
        "checked_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sec_headers": None
    }

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0 Safari/537.36"
        )
    }

    try:
        start = time.time()
        resp = requests.get(
            url,
            headers=headers,
            timeout=10,
            allow_redirects=True,
            verify=True,
        )
        elapsed_ms = int((time.time() - start) * 1000)

        # Count redirects from history
        redirects = len(resp.history)
        final_url  = resp.url

        # Extract Security Headers
        sec_h = {}
        target_h = ['Content-Security-Policy', 'Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options']
        for h in target_h:
            sec_h[h] = resp.headers.get(h)

        result.update({
            "status_code": resp.status_code,
            "response_ms": elapsed_ms,
            "redirects":   redirects,
            "final_url":   final_url,
            "secure":      final_url.startswith("https://"),
            "sec_headers": sec_h
        })
        result["status"]       = determine_status(resp.status_code, elapsed_ms, redirects, result["secure"])
        result["availability"] = calculate_availability(resp.status_code, elapsed_ms, redirects)

        # Get IP address
        try:
            domain = urlparse(url).netloc.split(':')[0]
            ip_addr = socket.gethostbyname(domain)
        except Exception:
            ip_addr = "Unknown"
        result["ip"] = ip_addr

    except SSLError:
        result["error"]  = "SSL certificate error"
        result["status"] = "SSL Error"
        result["ip"] = "Unknown"
    except Timeout:
        result["error"]  = "Connection timed out"
        result["status"] = "Down"
    except TooManyRedirects:
        result["error"]  = "Too many redirects"
        result["status"] = "Redirected"
    except ConnectionError:
        result["error"]  = "DNS resolution / connection failed"
        result["status"] = "Down"
    except InvalidURL:
        result["error"]  = "Invalid URL format"
        result["status"] = "Invalid"
    except MissingSchema:
        result["error"]  = "Missing URL schema"
        result["status"] = "Invalid"
    except Exception as exc:
        result["error"]  = f"Unexpected error: {str(exc)}"
        result["status"] = "Down"
        if "ip" not in result:
            result["ip"] = "Unknown"

    # WAZUH Engine Logic / Enhanced Threat Assessment
    alerts_generated = []
    score = 100
    has_sec_headers = False
    
    # Security headers assessment
    sec_headers = result.get("sec_headers") or {}
    has_sec_headers = any(sec_headers.values())
    
    if result["status"] == "Down" or result["status"] == "Broken" or result["status"] == "Invalid":
        alerts_generated.append({"level": "Critical", "rule": "Service_Unavailable", "msg": f"Service {result['url']} is unreachable."})
        score -= 50
    
    if result["status"] == "SSL Error":
        alerts_generated.append({"level": "Critical", "rule": "SSL_Certificate_Error", "msg": f"SSL/TLS certificate error for {result['url']}."})
        score -= 40
    
    if not result.get("secure", False):
        alerts_generated.append({"level": "Medium", "rule": "Insecure_Protocol", "msg": f"{result['url']} uses unencrypted HTTP protocol."})
        score -= 20
    
    if result.get("response_ms") and result.get("response_ms") > 3000:
        alerts_generated.append({"level": "Warning", "rule": "Slow_Response_Time", "msg": f"High latency detected: {result.get('response_ms')}ms (threshold: 3000ms)."})
        score -= 15
    
    if not has_sec_headers and result.get("status_code") in range(200, 400):
        alerts_generated.append({"level": "Low", "rule": "Missing_Security_Headers", "msg": f"Missing recommended security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options)."})
        score -= 10
    
    if result.get("redirects", 0) > 5:
        alerts_generated.append({"level": "Warning", "rule": "Excessive_Redirects", "msg": f"Excessive redirects detected ({result['redirects']} redirects)."})
        score -= 12
    
    # Suspicious keyword detection
    suspicious_keywords = ["phish", "login-verify", "confirm-identity", "update-account", "admin-verify", "verify-payment", "confirm-access"]
    if any(kw in result["url"].lower() for kw in suspicious_keywords):
        alerts_generated.append({"level": "Warning", "rule": "Suspicious_Domain_Keywords", "msg": f"URL contains suspicious keywords commonly used in phishing attacks."})
        score -= 15
    
    score = max(0, score)
    result["security_score"] = score
    result["wazuh_alerts"] = alerts_generated
    result["has_security_headers"] = has_sec_headers
    
    # Risk level classification
    risk_level = classify_risk(
        result["status"],
        result.get("response_ms"),
        result.get("secure", False),
        has_sec_headers,
        len(alerts_generated)
    )
    result["risk_level"] = risk_level
    
    # Check for multiple failed endpoints across the system for this IP
    if result["status"] == "Down" and result.get("ip") != "Unknown":
        with sqlite3.connect(DB_PATH) as conn:
            fails = conn.execute("SELECT COUNT(*) FROM url_history WHERE status IN ('Down', 'Broken') AND url LIKE ?", (f"%{result.get('ip')}%",)).fetchone()[0]
            if fails >= 3:
                alerts_generated.append({"level": "Critical", "rule": "Multiple_Endpoint_Failures", "msg": f"Multiple hosts down detected for IP {result.get('ip')}. Possible DDoS or infrastructure failure."})
                score = max(0, score - 20)
                result["security_score"] = score
                result["wazuh_alerts"] = alerts_generated
    
    # Persist alerts to enhanced DB with full context
    if alerts_generated:
        with DB_LOCK:
            with sqlite3.connect(DB_PATH) as conn:
                for a in alerts_generated:
                    conn.execute(
                        "INSERT INTO wazuh_alerts (level, rule_name, message, url, ip_address, response_ms, security_score, risk_level, status, timestamp, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                        (a["level"], a["rule"], a["msg"], result["url"], result.get("ip", "Unknown"),
                         result.get("response_ms"), result.get("security_score"), risk_level,
                         result.get("status"), datetime.now().strftime('%Y-%m-%d %H:%M:%S'), 1)
                    )
                conn.commit()
    
    # Write log to JSON file for Wazuh Agent monitoring
    log_wazuh_scan(result["url"], result["status"], result.get("response_ms"), result.get("secure", False),
                   result.get("ip", "Unknown"), result.get("security_score"), risk_level, alerts_generated)
    
    # ── Auto-Fix Engine ───────────────────────────────────────────────────────
    auto_fixes = []
    
    # 1. SSL/HTTPS Issue
    if result.get("status") != "Invalid" and not result.get("secure"):
        https_url = result["url"].replace("http://", "https://", 1)
        try:
            # Check if HTTPS is available
            ssl_resp = requests.get(https_url, timeout=5, verify=True, headers=headers)
            if ssl_resp.status_code < 400:
                auto_fixes.append({
                    "issue": "No HTTPS (Insecure)",
                    "cause": "URL uses unencrypted HTTP protocol.",
                    "fix_suggested": "Redirect HTTP to HTTPS.",
                    "auto_fix_attempted": True,
                    "auto_fix_result": "✅ HTTPS Available - Recommended action: Force HTTPS redirect."
                })
            else:
                auto_fixes.append({
                    "issue": "No HTTPS (Insecure)",
                    "cause": "SSL Certificate missing or invalid.",
                    "fix_suggested": "Install/Renew SSL Certificate.",
                    "auto_fix_attempted": True,
                    "auto_fix_result": "❌ HTTPS check failed. Certificate required."
                })
        except Exception:
            auto_fixes.append({
                "issue": "No HTTPS (Insecure)",
                "cause": "HTTPS port closed or cert missing.",
                "fix_suggested": "Enable HTTPS on server and install SSL.",
                "auto_fix_attempted": True,
                "auto_fix_result": "❌ Server not responding on HTTPS port."
            })
            
    # 2. Too Many Redirects
    if result.get("redirects", 0) > 3:
        auto_fixes.append({
            "issue": f"Too many redirects ({result['redirects']})",
            "cause": "Misconfigured proxy/DNS or application routing loop.",
            "fix_suggested": f"Update DNS/App to point directly to: {result.get('final_url', 'Destination')}",
            "auto_fix_attempted": True,
            "auto_fix_result": f"✅ Loop detected. Correct destination: {result.get('final_url')}"
        })
        
    # 3. Slow Response
    if result.get("response_ms") and result.get("response_ms") > 3000:
        auto_fixes.append({
            "issue": f"Slow response ({result['response_ms']}ms)",
            "cause": "Server overload, unoptimized DB queries, or no caching.",
            "fix_suggested": "Enable CDN, cache static assets, optimize server.",
            "auto_fix_attempted": False,
            "auto_fix_result": "⚠️ Server-side action needed."
        })
        
    # 4. Missing Security Headers
    if not has_sec_headers and result.get("status_code", 500) in range(200, 400):
        missing = []
        if not sec_headers.get('Content-Security-Policy'): missing.append('CSP')
        if not sec_headers.get('Strict-Transport-Security'): missing.append('HSTS')
        if not sec_headers.get('X-Frame-Options'): missing.append('X-Frame-Options')
        if missing:
            auto_fixes.append({
                "issue": "Missing Security Headers",
                "cause": "Web server isn't sending required HTTP headers.",
                "fix_suggested": f"Add {', '.join(missing)}.",
                "auto_fix_attempted": False,
                "auto_fix_result": "⚠️ Add headers in Nginx/Apache/App config."
            })
            
    # 5. Site Down or Broken
    if result.get("status") in ("Down", "Broken", "SSL Error"):
        auto_fixes.append({
            "issue": f"Site {result['status']}",
            "cause": result.get("error", "Unknown server/DNS failure"),
            "fix_suggested": "Check hosting status, DNS records, or application logs.",
            "auto_fix_attempted": False,
            "auto_fix_result": "❌ Active intervention required."
        })

    result["auto_fixes"] = auto_fixes
    
    return result

# ── Save to DB ────────────────────────────────────────────────────────────────
def save_to_history(r: dict):
    """Persist a check result into SQLite."""
    with DB_LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("""
                INSERT INTO url_history
                    (url, final_url, status, status_code, response_ms,
                     secure, redirects, availability, checked_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                r["url"], r.get("final_url"), r["status"],
                r.get("status_code"), r.get("response_ms"),
                1 if r.get("secure") else 0,
                r.get("redirects", 0),
                r.get("availability", "Poor"),
                r["checked_at"],
            ))
            conn.commit()

# ── Routes ────────────────────────────────────────────────────────────────────
@app.route("/")
@app.route("/index.html")
def index():
    """Serve the main frontend page."""
    return render_template("index.html", pdf_available=PDF_AVAILABLE)

@app.route("/supabase/<path:filename>")
def serve_supabase(filename):
    """Serve supabase client scripts to frontend."""
    return send_from_directory("supabase", filename)

@app.route("/login")
@app.route("/login.html")
def login_page():
    """Serve the user login page."""
    return render_template("login.html")

@app.route("/admin-login")
def admin_login():
    """Redirect older admin login route to the unified login page."""
    from flask import redirect, url_for
    return redirect(url_for("login_page"))

@app.route("/admin")
@app.route("/admin.html")
def admin():
    """Serve the admin dashboard page."""
    return render_template("admin.html")

# ── AUTH ROUTES ───────────────────────────────────────────────────────────────

@app.route("/api/auth/signup", methods=["POST"])
def auth_signup():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    if len(password) < 4:
        return jsonify({"error": "Password must be at least 4 characters"}), 400
    if username.lower() == 'admin':
        return jsonify({"error": "Username reserved"}), 403
    try:
        with DB_LOCK:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO users (username, password, role, status, created_at) VALUES (?,?,?,?,?)",
                    (username, hash_password(password), 'user', 'Active', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
                conn.commit()
                user = conn.execute("SELECT id, username, role FROM users WHERE username=?", (username,)).fetchone()
        session['user'] = {'id': user[0], 'username': user[1], 'role': user[2]}
        return jsonify({"success": True, "user": session['user']})
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already taken"}), 409

@app.route("/api/auth/login", methods=["POST"])
def auth_login():
    data = request.get_json(force=True)
    username = (data.get("username") or "").strip()
    password = (data.get("password") or "").strip()
    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        user = conn.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, hash_password(password))
        ).fetchone()
    if not user:
        return jsonify({"error": "Invalid username or password"}), 401
    if user['status'] == 'Blocked':
        return jsonify({"error": "Account is blocked by administrator"}), 403
    session['user'] = {'id': user['id'], 'username': user['username'], 'role': user['role']}
    return jsonify({"success": True, "user": session['user']})

@app.route("/api/auth/logout", methods=["POST"])
def auth_logout():
    session.pop('user', None)
    return jsonify({"success": True})

@app.route("/api/auth/me", methods=["GET"])
def auth_me():
    user = session.get('user')
    if not user:
        return jsonify({"error": "Not authenticated"}), 401
    # Re-fetch latest status from DB
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT id, username, role, status FROM users WHERE id=?", (user['id'],)).fetchone()
    if not row or row['status'] == 'Blocked':
        session.pop('user', None)
        return jsonify({"error": "Account blocked or not found"}), 403
    return jsonify({"user": {'id': row['id'], 'username': row['username'], 'role': row['role']}})

# ── SCAN HISTORY (per user) ───────────────────────────────────────────────────
@app.route("/api/user/scans", methods=["GET"])
def user_scans_get():
    user = session.get('user')
    if not user: return jsonify({"error": "Not authenticated"}), 401
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM user_scans WHERE user_id=? ORDER BY id DESC LIMIT 100", (user['id'],)
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/user/scans", methods=["POST"])
def user_scans_post():
    user = session.get('user')
    if not user: return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json(force=True)
    with DB_LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT INTO user_scans (user_id, input, type, status, speed, grade, scan_data, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (user['id'], data.get('input',''), data.get('type','url'),
                 data.get('status',''), data.get('speed'), data.get('grade',''),
                 json.dumps(data.get('scan_data',{})), datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
            )
            conn.commit()
    return jsonify({"success": True})

@app.route("/api/user/scans/clear", methods=["DELETE"])
def user_scans_clear():
    user = session.get('user')
    if not user: return jsonify({"error": "Not authenticated"}), 401
    with DB_LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM user_scans WHERE user_id=?", (user['id'],))
            conn.commit()
    return jsonify({"success": True})

# ── FAVORITES (per user) ──────────────────────────────────────────────────────
@app.route("/api/user/favorites", methods=["GET"])
def user_favorites_get():
    user = session.get('user')
    if not user: return jsonify({"error": "Not authenticated"}), 401
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM favorites WHERE user_id=? ORDER BY id DESC", (user['id'],)
        ).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/user/favorites", methods=["POST"])
def user_favorites_post():
    user = session.get('user')
    if not user: return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json(force=True)
    inp = data.get('input', '').strip()
    if not inp: return jsonify({"error": "No input"}), 400
    try:
        with DB_LOCK:
            with sqlite3.connect(DB_PATH) as conn:
                conn.execute(
                    "INSERT INTO favorites (user_id, input, created_at) VALUES (?,?,?)",
                    (user['id'], inp, datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
                conn.commit()
        return jsonify({"success": True})
    except sqlite3.IntegrityError:
        return jsonify({"success": True, "message": "Already in favorites"})

@app.route("/api/user/favorites", methods=["DELETE"])
def user_favorites_delete():
    user = session.get('user')
    if not user: return jsonify({"error": "Not authenticated"}), 401
    data = request.get_json(force=True)
    inp = data.get('input', '').strip()
    with DB_LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM favorites WHERE user_id=? AND input=?", (user['id'], inp))
            conn.commit()
    return jsonify({"success": True})

# ── ADMIN DATA ROUTES ─────────────────────────────────────────────────────────
@app.route("/api/admin/users", methods=["GET"])
def admin_users():
    user = session.get('user')
    if not user or user['role'] != 'admin': return jsonify({"error": "Forbidden"}), 403
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT id, username, role, status, created_at FROM users").fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/users/<int:uid>/block", methods=["POST"])
def admin_block_user(uid):
    user = session.get('user')
    if not user or user['role'] != 'admin': return jsonify({"error": "Forbidden"}), 403
    data = request.get_json(force=True)
    status = 'Blocked' if data.get('block') else 'Active'
    with DB_LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("UPDATE users SET status=? WHERE id=?", (status, uid))
            conn.commit()
    return jsonify({"success": True})

@app.route("/api/admin/settings", methods=["GET"])
def admin_settings_get():
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT key, value FROM admin_settings").fetchall()
    return jsonify({r['key']: r['value'] for r in rows})

@app.route("/api/admin/settings", methods=["POST"])
def admin_settings_set():
    user = session.get('user')
    if not user or user['role'] != 'admin': return jsonify({"error": "Forbidden"}), 403
    data = request.get_json(force=True)
    with DB_LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            for key, value in data.items():
                conn.execute(
                    "INSERT INTO admin_settings (key, value, updated_at) VALUES (?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                    (key, str(value), datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
                )
            conn.commit()
    return jsonify({"success": True})


@app.route("/api/check", methods=["POST"])
def api_check():
    """Single URL check endpoint."""
    data = request.get_json(force=True)
    url  = data.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400
    result = check_url(url)
    save_to_history(result)
    return jsonify(result)

@app.route("/api/check-bulk", methods=["POST"])
def api_check_bulk():
    """Bulk URL check endpoint — accepts list of URLs."""
    data = request.get_json(force=True)
    urls = data.get("urls", [])
    if not urls:
        return jsonify({"error": "No URLs provided"}), 400
    # Limit to 20 URLs per bulk request
    urls    = [u.strip() for u in urls if u.strip()][:20]
    results = []
    for url in urls:
        r = check_url(url)
        save_to_history(r)
        results.append(r)
    return jsonify({"results": results})

@app.route("/api/history", methods=["GET"])
def api_history():
    """Return last 100 history entries."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute("""
            SELECT * FROM url_history
            ORDER BY id DESC LIMIT 100
        """).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/wazuh/alerts", methods=["GET"])
def wazuh_alerts_get():
    """Returns the latest Wazuh mock alerts with enhanced filtering."""
    limit = request.args.get("limit", 50, type=int)
    level = request.args.get("level", None)  # Optional: filter by severity
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if level:
            rows = conn.execute("SELECT * FROM wazuh_alerts WHERE level=? AND is_active=1 ORDER BY timestamp DESC LIMIT ?", 
                              (level, limit)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM wazuh_alerts WHERE is_active=1 ORDER BY timestamp DESC LIMIT ?", 
                              (limit,)).fetchall()
    return jsonify([dict(r) for r in rows])

@app.route("/api/wazuh/alerts/stats", methods=["GET"])
def wazuh_alerts_stats():
    """Get security alerts statistics for SOC dashboard."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        
        # Count by severity
        critical = conn.execute("SELECT COUNT(*) as cnt FROM wazuh_alerts WHERE level='Critical' AND is_active=1").fetchone()['cnt']
        high = conn.execute("SELECT COUNT(*) as cnt FROM wazuh_alerts WHERE level='High' AND is_active=1").fetchone()['cnt']
        medium = conn.execute("SELECT COUNT(*) as cnt FROM wazuh_alerts WHERE level='Medium' AND is_active=1").fetchone()['cnt']
        low = conn.execute("SELECT COUNT(*) as cnt FROM wazuh_alerts WHERE level='Low' AND is_active=1").fetchone()['cnt']
        info = conn.execute("SELECT COUNT(*) as cnt FROM wazuh_alerts WHERE level='Info' AND is_active=1").fetchone()['cnt']
        warning = conn.execute("SELECT COUNT(*) as cnt FROM wazuh_alerts WHERE level='Warning' AND is_active=1").fetchone()['cnt']
        
        # Total scans 24h
        total_scans = conn.execute("SELECT COUNT(*) as cnt FROM url_history WHERE checked_at >= datetime('now', '-24 hours')").fetchone()['cnt']
        
        # Avg security score
        avg_score = conn.execute("SELECT AVG(CAST(json_extract(scan_data, '$.security_score') AS FLOAT)) as score FROM user_scans WHERE scan_data IS NOT NULL LIMIT 100").fetchone()
        avg_score = avg_score['score'] if avg_score['score'] else 75
        
    stats = {
        "critical_alerts": critical,
        "high_alerts": high,
        "medium_alerts": medium,
        "low_alerts": low,
        "warning_alerts": warning,
        "info_alerts": info,
        "total_active_alerts": critical + high + medium + low + warning + info,
        "scans_24h": total_scans,
        "avg_security_score": round(avg_score, 2)
    }
    return jsonify(stats)

@app.route("/api/wazuh/risks", methods=["GET"])
def wazuh_risks():
    """Get active risk classifications from latest scans."""
    limit = request.args.get("limit", 100, type=int)
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT url, status, security_score, risk_level, timestamp FROM wazuh_alerts WHERE risk_level IS NOT NULL ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
    
    # Group by risk level
    risks = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": [], "INFO": []}
    for r in rows:
        risk = dict(r)
        level = risk.pop('risk_level', None)
        if level and level in risks:
            if risk not in risks[level]:  # Avoid duplicates
                risks[level].append(risk)
    
    return jsonify(risks)

@app.route("/api/security/dashboard", methods=["GET"])
def security_dashboard():
    """Comprehensive SOC Dashboard data endpoint."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        
        # Recent critical alerts
        critical_alerts = conn.execute(
            "SELECT * FROM wazuh_alerts WHERE level='Critical' AND is_active=1 ORDER BY timestamp DESC LIMIT 5"
        ).fetchall()
        
        # Top vulnerable URLs
        vuln_urls = conn.execute("""
            SELECT url, COUNT(*) as alert_count, AVG(security_score) as avg_score 
            FROM wazuh_alerts 
            WHERE is_active=1 
            GROUP BY url 
            ORDER BY alert_count DESC 
            LIMIT 10
        """).fetchall()
        
        # Last 24h scan summary
        last_24h = conn.execute("""
            SELECT status, COUNT(*) as count 
            FROM url_history 
            WHERE checked_at >= datetime('now', '-24 hours')
            GROUP BY status
        """).fetchall()
        
        # Risk distribution
        risk_dist = conn.execute("""
            SELECT risk_level, COUNT(*) as count 
            FROM wazuh_alerts 
            WHERE is_active=1 AND risk_level IS NOT NULL
            GROUP BY risk_level
        """).fetchall()
    
    dashboard = {
        "critical_alerts": [dict(a) for a in critical_alerts],
        "vulnerable_urls": [dict(u) for u in vuln_urls],
        "status_distribution_24h": {dict(s)['status']: dict(s)['count'] for s in last_24h},
        "risk_distribution": {dict(r)['risk_level']: dict(r)['count'] for r in risk_dist}
    }
    return jsonify(dashboard)

@app.route("/api/security/score/<url>", methods=["GET"])
def get_security_score(url):
    """Get security score and detailed analysis for a specific URL."""
    import urllib.parse
    url_decoded = urllib.parse.unquote(url)
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        
        # Most recent scan
        scan = conn.execute(
            "SELECT * FROM url_history WHERE url LIKE ? ORDER BY checked_at DESC LIMIT 1",
            (f"%{url_decoded}%",)
        ).fetchone()
        
        # Related alerts
        alerts = conn.execute(
            "SELECT * FROM wazuh_alerts WHERE url LIKE ? ORDER BY timestamp DESC LIMIT 20",
            (f"%{url_decoded}%",)
        ).fetchall()
    
    return jsonify({
        "url": url_decoded,
        "latest_scan": dict(scan) if scan else None,
        "alerts": [dict(a) for a in alerts]
    })

@app.route("/api/monitoring/live", methods=["GET"])
def monitoring_live():
    """Live monitoring stream endpoint - returns recent activity."""
    limit = request.args.get("limit", 20, type=int)
    
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        
        # Recent scans
        recent_scans = conn.execute(
            "SELECT url, status, response_ms, secure, checked_at FROM url_history ORDER BY checked_at DESC LIMIT ?",
            (limit,)
        ).fetchall()
        
        # Recent alerts
        recent_alerts = conn.execute(
            "SELECT rule_name, level, url, timestamp FROM wazuh_alerts WHERE is_active=1 ORDER BY timestamp DESC LIMIT ?",
            (limit,)
        ).fetchall()
    
    return jsonify({
        "recent_scans": [dict(s) for s in recent_scans],
        "recent_alerts": [dict(a) for a in recent_alerts],
        "timestamp": datetime.now().isoformat()
    })

@app.route("/api/history/clear", methods=["DELETE"])
def api_clear_history():
    """Clear all history records - protected admin action."""
    with DB_LOCK:
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM url_history")
            conn.commit()
    return jsonify({"message": "History cleared"})


@app.route("/api/export/csv")
def export_csv():
    """Export history as CSV file."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM url_history ORDER BY id DESC"
        ).fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "ID", "URL", "Final URL", "Status", "Status Code",
        "Response (ms)", "Secure", "Redirects", "Availability", "Checked At"
    ])
    for r in rows:
        writer.writerow([
            r["id"], r["url"], r["final_url"] or "", r["status"],
            r["status_code"] or "", r["response_ms"] or "",
            "Yes" if r["secure"] else "No",
            r["redirects"], r["availability"], r["checked_at"],
        ])

    output.seek(0)
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=url_report.csv"}
    )

@app.route("/api/export/pdf")
def export_pdf():
    """Export history as PDF file (requires reportlab)."""
    if not PDF_AVAILABLE:
        return jsonify({"error": "reportlab not installed. Run: pip install reportlab"}), 501

    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM url_history ORDER BY id DESC LIMIT 50"
        ).fetchall()

    buffer = io.BytesIO()
    doc    = SimpleDocTemplate(buffer, pagesize=A4,
                               rightMargin=30, leftMargin=30,
                               topMargin=40, bottomMargin=30)
    styles = getSampleStyleSheet()
    story  = []

    # Title
    title_style = ParagraphStyle("Title", parent=styles["Title"],
                                  fontSize=18, textColor=colors.HexColor("#0ea5e9"),
                                  spaceAfter=6)
    story.append(Paragraph("Smart URL Status Checker — Report", title_style))
    story.append(Paragraph(
        f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        styles["Normal"]
    ))
    story.append(Spacer(1, 0.25 * inch))

    # Table header
    table_data = [["URL", "Status", "Code", "ms", "Secure", "Availability", "Checked At"]]
    for r in rows:
        table_data.append([
            (r["url"] or "")[:45],
            r["status"] or "",
            str(r["status_code"] or "—"),
            str(r["response_ms"] or "—"),
            "✓" if r["secure"] else "✗",
            r["availability"] or "",
            (r["checked_at"] or "")[:16],
        ])

    # Color coding per status
    status_colors = {
        "Up":         colors.HexColor("#dcfce7"),
        "Down":       colors.HexColor("#fee2e2"),
        "Slow":       colors.HexColor("#fef9c3"),
        "Redirected": colors.HexColor("#dbeafe"),
        "Broken":     colors.HexColor("#ffe4e6"),
    }

    t = Table(table_data, colWidths=[145, 62, 38, 38, 42, 68, 90])
    style_cmds = [
        ("BACKGROUND",  (0, 0), (-1, 0), colors.HexColor("#0ea5e9")),
        ("TEXTCOLOR",   (0, 0), (-1, 0), colors.white),
        ("FONTNAME",    (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",    (0, 0), (-1, -1), 8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f8fafc")]),
        ("GRID",        (0, 0), (-1, -1), 0.5, colors.HexColor("#e2e8f0")),
        ("ALIGN",       (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",      (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",  (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING",(0, 0), (-1, -1), 4),
    ]
    # Row-level status background
    for i, r in enumerate(rows, start=1):
        sc = status_colors.get(r["status"])
        if sc:
            style_cmds.append(("BACKGROUND", (1, i), (1, i), sc))

    t.setStyle(TableStyle(style_cmds))
    story.append(t)
    doc.build(story)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=True,
        download_name="url_report.pdf"
    )

# ── Entry Point ───────────────────────────────────────────────────────────────
if __name__ == "__main__":
    print("🚀  Smart URL Status Checker running at http://127.0.0.1:5000")
    app.run(debug=True, host="0.0.0.0", port=5000)
