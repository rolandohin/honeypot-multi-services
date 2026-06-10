# ============================================================
#  modules/http_module.py — Honeypot HTTP
#  Sert de fausses pages admin et capture les soumissions
# ============================================================

import os
import sys
import json
from flask import Flask, request, redirect, jsonify, Response
from markupsafe import escape
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from config import PORTS
from logger import log_connection, log_http, get_stats, log

app = Flask(__name__)

# ──────────────────────────────────────────────
#  Templates HTML — Pages leurres réalistes
# ──────────────────────────────────────────────

LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Admin Panel — Corporate IT</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Segoe UI', Arial, sans-serif;
      background: #1a1a2e;
      display: flex; align-items: center; justify-content: center;
      min-height: 100vh;
    }
    .card {
      background: #16213e;
      border: 1px solid #0f3460;
      border-radius: 10px;
      padding: 40px;
      width: 380px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
    }
    .logo {
      text-align: center;
      margin-bottom: 28px;
    }
    .logo h1 { color: #e94560; font-size: 22px; letter-spacing: 2px; }
    .logo p  { color: #888; font-size: 12px; margin-top: 4px; }
    label { color: #aaa; font-size: 13px; display: block; margin-bottom: 6px; }
    input {
      width: 100%; padding: 11px 14px;
      background: #0f3460; border: 1px solid #1a4a7a;
      border-radius: 6px; color: #fff; font-size: 14px;
      margin-bottom: 16px; outline: none;
    }
    input:focus { border-color: #e94560; }
    button {
      width: 100%; padding: 12px;
      background: #e94560; border: none;
      border-radius: 6px; color: #fff;
      font-size: 15px; font-weight: 600;
      cursor: pointer; letter-spacing: 1px;
    }
    button:hover { background: #c73652; }
    .error {
      background: rgba(233,69,96,0.15);
      border: 1px solid #e94560;
      color: #e94560; border-radius: 6px;
      padding: 10px 14px; font-size: 13px;
      margin-bottom: 16px; text-align: center;
    }
    .footer { color: #555; font-size: 11px; text-align: center; margin-top: 20px; }
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <h1>⚙ ADMIN PANEL</h1>
      <p>Corporate IT Management System v3.2</p>
    </div>
    <form method="POST" action="/login">
      <label>Username</label>
      <input type="text" name="username" placeholder="admin" autocomplete="off" required>
      <label>Password</label>
      <input type="password" name="password" placeholder="••••••••" required>
      <button type="submit">SIGN IN →</button>
    </form>
    <div class="footer">© 2024 Corporate IT Dept. — Unauthorized access is prohibited.</div>
  </div>
</body>
</html>"""


FAKE_DASHBOARD = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Admin Dashboard — Corporate IT</title>
  <style>
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; }
    .topbar {
      background: #161b22; border-bottom: 1px solid #30363d;
      padding: 14px 30px; display: flex;
      justify-content: space-between; align-items: center;
    }
    .topbar h1 { color: #58a6ff; font-size: 18px; }
    .topbar span { color: #8b949e; font-size: 13px; }
    .content { padding: 30px; }
    .cards { display: grid; grid-template-columns: repeat(4,1fr); gap: 16px; margin-bottom: 30px; }
    .card {
      background: #161b22; border: 1px solid #30363d;
      border-radius: 8px; padding: 20px;
    }
    .card h3 { color: #8b949e; font-size: 12px; text-transform: uppercase; margin-bottom: 8px; }
    .card .val { font-size: 28px; font-weight: 700; color: #58a6ff; }
    .card .sub { color: #8b949e; font-size: 12px; margin-top: 4px; }
    table { width: 100%; border-collapse: collapse; }
    th { background: #21262d; color: #8b949e; font-size: 12px;
         padding: 10px 14px; text-align: left; border-bottom: 1px solid #30363d; }
    td { padding: 10px 14px; border-bottom: 1px solid #21262d; font-size: 13px; color: #c9d1d9; }
    tr:hover td { background: #161b22; }
    .section { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .section h2 { color: #c9d1d9; font-size: 15px; margin-bottom: 16px; }
    .badge {
      display: inline-block; padding: 2px 8px;
      border-radius: 12px; font-size: 11px; font-weight: 600;
    }
    .badge-green  { background: rgba(63,185,80,0.2); color: #3fb950; }
    .badge-red    { background: rgba(248,81,73,0.2); color: #f85149; }
    .badge-blue   { background: rgba(88,166,255,0.2); color: #58a6ff; }
    .loading { color: #8b949e; font-size: 13px; padding: 20px; text-align: center; }
  </style>
</head>
<body>
  <div class="topbar">
    <h1>⚙ Admin Dashboard</h1>
    <span>Welcome, __USERNAME__ — Session started __TIME__</span>
  </div>
  <div class="content">
    <div class="cards">
      <div class="card"><h3>Active Users</h3><div class="val">247</div><div class="sub">↑ 12 since yesterday</div></div>
      <div class="card"><h3>Servers</h3><div class="val">18</div><div class="sub">16 online, 2 maintenance</div></div>
      <div class="card"><h3>Alerts</h3><div class="val" style="color:#f85149">3</div><div class="sub">Requires attention</div></div>
      <div class="card"><h3>Uptime</h3><div class="val" style="color:#3fb950">99.8%</div><div class="sub">Last 30 days</div></div>
    </div>
    <div class="section">
      <h2>📂 Recent Files</h2>
      <table>
        <tr><th>Name</th><th>Type</th><th>Size</th><th>Modified</th></tr>
        <tr><td>/etc/passwd</td><td>Config</td><td>2.1 KB</td><td>2024-01-15</td></tr>
        <tr><td>/var/log/auth.log</td><td>Log</td><td>145 KB</td><td>2024-01-15</td></tr>
        <tr><td>/home/admin/.ssh/id_rsa</td><td>Key</td><td>1.7 KB</td><td>2024-01-10</td></tr>
        <tr><td>/opt/backup/db_2024.sql</td><td>Backup</td><td>4.2 MB</td><td>2024-01-14</td></tr>
      </table>
    </div>
    <div class="section">
      <h2>🖥 Server Status</h2>
      <table>
        <tr><th>Host</th><th>IP</th><th>Status</th><th>CPU</th><th>RAM</th></tr>
        <tr><td>web-prod-01</td><td>10.0.1.10</td><td><span class="badge badge-green">ONLINE</span></td><td>23%</td><td>41%</td></tr>
        <tr><td>db-prod-01</td><td>10.0.1.20</td><td><span class="badge badge-green">ONLINE</span></td><td>67%</td><td>78%</td></tr>
        <tr><td>vpn-gateway</td><td>10.0.1.5</td><td><span class="badge badge-green">ONLINE</span></td><td>5%</td><td>12%</td></tr>
        <tr><td>backup-srv</td><td>10.0.1.30</td><td><span class="badge badge-red">MAINTENANCE</span></td><td>—</td><td>—</td></tr>
      </table>
    </div>
  </div>
</body>
</html>"""


# ──────────────────────────────────────────────
#  Routes Flask
# ──────────────────────────────────────────────

@app.before_request
def capture_all():
    """Capture TOUTES les requêtes entrantes."""
    ip = request.remote_addr
    body = ""
    if request.method == "POST":
        body = str(request.form.to_dict())

    log_http(
        src_ip=ip,
        method=request.method,
        path=request.path,
        user_agent=request.headers.get("User-Agent", ""),
        body=body
    )


@app.route("/")
@app.route("/index.html")
def index():
    return redirect("/login")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        # Page statique, aucune donnee dynamique -> servie telle quelle
        return Response(LOGIN_PAGE, mimetype="text/html")

    username = request.form.get("username", "")
    password = request.form.get("password", "")
    ip       = request.remote_addr

    # Enregistre la tentative
    log_connection(
        service="http",
        src_ip=ip,
        src_port=request.environ.get("REMOTE_PORT", 0),
        username=username,
        password=password,
        success=True,    # On laisse toujours passer
    )

    # Faux dashboard : on insere le username SANS passer par le moteur de
    # template Jinja (sinon SSTI). On echappe strictement l'entree attaquant
    # avec markupsafe.escape, puis simple remplacement de marqueurs statiques.
    safe_username = str(escape(username))
    safe_time     = datetime.now().strftime("%H:%M:%S")
    page = (FAKE_DASHBOARD
            .replace("__USERNAME__", safe_username)
            .replace("__TIME__", safe_time))
    return Response(page, mimetype="text/html")


@app.route("/admin")
@app.route("/wp-admin")
@app.route("/administrator")
@app.route("/phpmyadmin")
@app.route("/panel")
def admin_redirect():
    """Toutes les URLs admin classiques redirigent vers /login."""
    return redirect("/login")


@app.route("/api/stats")
def api_stats():
    """Endpoint JSON pour le dashboard honeypot (usage interne)."""
    return jsonify(get_stats())


@app.errorhandler(404)
def not_found(e):
    """Capture les scans de paths inconnus."""
    return redirect("/login"), 302


# ──────────────────────────────────────────────
#  Démarrage du serveur
# ──────────────────────────────────────────────

def start_http_server():
    port = PORTS["http"]
    log.info("[HTTP] 🟢 Honeypot HTTP démarré sur port %s", port)
    # use_reloader=False obligatoire en mode thread
    app.run(host="0.0.0.0", port=port, use_reloader=False, threaded=True)


if __name__ == "__main__":
    from logger import init_db
    init_db()
    start_http_server()
