# ============================================================
#  dashboard.py — Dashboard de supervision du honeypot
#  Interface web temps réel — à lancer séparément de main.py
#  Usage : python dashboard.py  →  http://<IP_VM>:5000
# ============================================================

import sqlite3
import json
import os
import sys
from flask import Flask, render_template_string, jsonify
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from config import DB_PATH

app = Flask(__name__)

# ──────────────────────────────────────────────
#  Fonctions de requêtes DB
# ──────────────────────────────────────────────

def query(sql, params=()):
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(sql, params)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows

def scalar(sql, params=()):
    if not os.path.exists(DB_PATH):
        return 0
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute(sql, params)
    val = c.fetchone()
    conn.close()
    return val[0] if val else 0


# ──────────────────────────────────────────────
#  API JSON (polling toutes les 5s par le front)
# ──────────────────────────────────────────────

@app.route("/api/data")
def api_data():
    # Stats globales
    total      = scalar("SELECT COUNT(*) FROM connections")
    unique_ips = scalar("SELECT COUNT(DISTINCT src_ip) FROM connections")
    total_cmds = scalar("SELECT COUNT(*) FROM commands")
    last_hour  = scalar(
        "SELECT COUNT(*) FROM connections WHERE timestamp > ?",
        ((datetime.now() - timedelta(hours=1)).isoformat(),)
    )

    # Par service
    by_service = {r["service"]: r["cnt"] for r in
                  query("SELECT service, COUNT(*) as cnt FROM connections GROUP BY service")}

    # Top 8 IPs
    top_ips = query("""
        SELECT src_ip, COUNT(*) as cnt, MAX(timestamp) as last_seen
        FROM connections GROUP BY src_ip ORDER BY cnt DESC LIMIT 8
    """)

    # Top 8 credentials
    top_creds = query("""
        SELECT username, password, COUNT(*) as cnt
        FROM connections WHERE username IS NOT NULL
        GROUP BY username, password ORDER BY cnt DESC LIMIT 8
    """)

    # Dernières 15 connexions
    recent = query("""
        SELECT timestamp, service, src_ip, username, password, success
        FROM connections ORDER BY id DESC LIMIT 15
    """)

    # Dernières commandes SSH
    recent_cmds = query("""
        SELECT cm.timestamp, cm.command, co.src_ip
        FROM commands cm
        JOIN connections co ON cm.connection_id = co.id
        ORDER BY cm.id DESC LIMIT 10
    """)

    # Activité par heure (24 dernières heures)
    hourly = defaultdict(int)
    rows = query("""
        SELECT timestamp FROM connections
        WHERE timestamp > ?
    """, ((datetime.now() - timedelta(hours=24)).isoformat(),))
    for r in rows:
        try:
            h = datetime.fromisoformat(r["timestamp"]).strftime("%H:00")
            hourly[h] += 1
        except Exception:
            pass

    return jsonify({
        "total": total,
        "unique_ips": unique_ips,
        "total_cmds": total_cmds,
        "last_hour": last_hour,
        "by_service": by_service,
        "top_ips": top_ips,
        "top_creds": top_creds,
        "recent": recent,
        "recent_cmds": recent_cmds,
        "hourly": dict(hourly),
        "generated_at": datetime.now().strftime("%H:%M:%S"),
    })


# ──────────────────────────────────────────────
#  Page HTML principale
# ──────────────────────────────────────────────

HTML = """<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>🍯 Honeypot — Supervision</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Exo+2:wght@300;400;600;800&display=swap" rel="stylesheet">
<style>
  :root {
    --bg:       #050a0f;
    --bg2:      #0a1520;
    --bg3:      #0f1e2d;
    --border:   #1a3a5c;
    --cyan:     #00d4ff;
    --green:    #00ff9d;
    --red:      #ff4757;
    --orange:   #ffa502;
    --purple:   #a855f7;
    --text:     #c8e6f5;
    --muted:    #4a7a9b;
    --mono:     'Share Tech Mono', monospace;
    --sans:     'Exo 2', sans-serif;
  }

  * { box-sizing: border-box; margin: 0; padding: 0; }

  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    min-height: 100vh;
    overflow-x: hidden;
  }

  /* Grille de fond animée */
  body::before {
    content: '';
    position: fixed; inset: 0; z-index: 0;
    background-image:
      linear-gradient(rgba(0,212,255,.03) 1px, transparent 1px),
      linear-gradient(90deg, rgba(0,212,255,.03) 1px, transparent 1px);
    background-size: 40px 40px;
    pointer-events: none;
  }

  .wrap { position: relative; z-index: 1; padding: 0 24px 40px; max-width: 1400px; margin: 0 auto; }

  /* ── HEADER ── */
  header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 20px 24px 16px;
    border-bottom: 1px solid var(--border);
    position: sticky; top: 0; z-index: 100;
    background: rgba(5,10,15,.95);
    backdrop-filter: blur(12px);
  }
  .logo {
    display: flex; align-items: center; gap: 14px;
  }
  .logo-icon {
    font-size: 28px;
    filter: drop-shadow(0 0 12px var(--cyan));
    animation: pulse 2s ease-in-out infinite;
  }
  @keyframes pulse {
    0%,100% { filter: drop-shadow(0 0 8px var(--cyan)); }
    50%      { filter: drop-shadow(0 0 20px var(--cyan)); }
  }
  .logo-text h1 {
    font-family: var(--sans); font-weight: 800; font-size: 18px;
    letter-spacing: 3px; color: var(--cyan); text-transform: uppercase;
  }
  .logo-text p {
    font-family: var(--mono); font-size: 10px; color: var(--muted);
    letter-spacing: 1px;
  }
  .header-right {
    display: flex; align-items: center; gap: 20px;
  }
  .live-badge {
    display: flex; align-items: center; gap: 6px;
    background: rgba(0,255,157,.08);
    border: 1px solid rgba(0,255,157,.3);
    border-radius: 20px; padding: 5px 12px;
    font-family: var(--mono); font-size: 11px; color: var(--green);
    letter-spacing: 1px;
  }
  .live-dot {
    width: 7px; height: 7px; border-radius: 50%;
    background: var(--green);
    animation: blink .9s ease-in-out infinite;
  }
  @keyframes blink { 0%,100%{opacity:1} 50%{opacity:.2} }
  .clock {
    font-family: var(--mono); font-size: 13px; color: var(--muted);
  }

  /* ── KPI CARDS ── */
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 16px;
    margin: 28px 0;
  }
  .kpi {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 22px 20px;
    position: relative;
    overflow: hidden;
    transition: border-color .3s, transform .2s;
  }
  .kpi:hover { border-color: var(--cyan); transform: translateY(-2px); }
  .kpi::before {
    content: '';
    position: absolute; top: 0; left: 0; right: 0; height: 2px;
  }
  .kpi.c1::before { background: linear-gradient(90deg, var(--cyan), transparent); }
  .kpi.c2::before { background: linear-gradient(90deg, var(--green), transparent); }
  .kpi.c3::before { background: linear-gradient(90deg, var(--orange), transparent); }
  .kpi.c4::before { background: linear-gradient(90deg, var(--purple), transparent); }
  .kpi-label {
    font-family: var(--mono); font-size: 10px; color: var(--muted);
    letter-spacing: 2px; text-transform: uppercase; margin-bottom: 10px;
  }
  .kpi-val {
    font-family: var(--sans); font-weight: 800; font-size: 38px;
    line-height: 1; transition: all .4s;
  }
  .kpi.c1 .kpi-val { color: var(--cyan); }
  .kpi.c2 .kpi-val { color: var(--green); }
  .kpi.c3 .kpi-val { color: var(--orange); }
  .kpi.c4 .kpi-val { color: var(--purple); }
  .kpi-sub { font-size: 11px; color: var(--muted); margin-top: 6px; }
  .kpi-icon {
    position: absolute; right: 18px; top: 50%; transform: translateY(-50%);
    font-size: 36px; opacity: .08;
  }

  /* ── LAYOUT GRILLE ── */
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 16px; }
  .grid3 { display: grid; grid-template-columns: 2fr 1fr; gap: 16px; margin-bottom: 16px; }

  /* ── PANELS ── */
  .panel {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    transition: border-color .3s;
  }
  .panel:hover { border-color: rgba(0,212,255,.25); }
  .panel-title {
    font-family: var(--mono); font-size: 11px; color: var(--cyan);
    letter-spacing: 2px; text-transform: uppercase;
    margin-bottom: 16px;
    display: flex; align-items: center; gap: 8px;
  }
  .panel-title::before {
    content: ''; width: 3px; height: 14px;
    background: var(--cyan); border-radius: 2px;
  }

  /* ── SERVICE BARS ── */
  .svc-list { display: flex; flex-direction: column; gap: 12px; }
  .svc-row { display: flex; align-items: center; gap: 12px; }
  .svc-name {
    font-family: var(--mono); font-size: 12px;
    width: 50px; color: var(--text);
  }
  .svc-bar-wrap {
    flex: 1; height: 8px;
    background: var(--bg3); border-radius: 4px; overflow: hidden;
  }
  .svc-bar {
    height: 100%; border-radius: 4px;
    transition: width .8s cubic-bezier(.4,0,.2,1);
  }
  .svc-cnt {
    font-family: var(--mono); font-size: 12px; color: var(--muted);
    width: 32px; text-align: right;
  }
  .svc-ssh   .svc-bar { background: var(--cyan); }
  .svc-http  .svc-bar { background: var(--green); }
  .svc-ftp   .svc-bar { background: var(--orange); }
  .svc-smtp  .svc-bar { background: var(--purple); }

  /* ── BAR CHART HORAIRE ── */
  .chart-wrap {
    display: flex; align-items: flex-end; gap: 3px;
    height: 80px; padding-top: 8px;
  }
  .bar-col { flex: 1; display: flex; flex-direction: column; align-items: center; gap: 4px; }
  .bar-fill {
    width: 100%; border-radius: 3px 3px 0 0;
    background: linear-gradient(180deg, var(--cyan), rgba(0,212,255,.3));
    transition: height .6s ease; min-height: 2px;
  }
  .bar-label { font-family: var(--mono); font-size: 8px; color: var(--muted); }

  /* ── TABLES ── */
  table { width: 100%; border-collapse: collapse; }
  thead th {
    font-family: var(--mono); font-size: 9px; letter-spacing: 2px;
    color: var(--muted); text-transform: uppercase;
    padding: 0 10px 10px; text-align: left;
    border-bottom: 1px solid var(--border);
  }
  tbody tr {
    border-bottom: 1px solid rgba(26,58,92,.5);
    transition: background .15s;
  }
  tbody tr:hover { background: rgba(0,212,255,.04); }
  tbody td {
    padding: 9px 10px;
    font-family: var(--mono); font-size: 12px; color: var(--text);
  }
  .ip   { color: var(--cyan); }
  .user { color: var(--green); }
  .pass { color: var(--orange); }
  .cmd  { color: var(--purple); }
  .ts   { color: var(--muted); font-size: 10px; }
  .cnt  { color: var(--red); font-weight: 700; }

  /* ── BADGES SERVICE ── */
  .badge {
    display: inline-block; padding: 2px 7px;
    border-radius: 4px; font-size: 9px; font-weight: 700;
    font-family: var(--mono); letter-spacing: 1px;
    text-transform: uppercase;
  }
  .badge-ssh  { background: rgba(0,212,255,.15);  color: var(--cyan); }
  .badge-http { background: rgba(0,255,157,.15);  color: var(--green); }
  .badge-ftp  { background: rgba(255,165,2,.15);  color: var(--orange); }
  .badge-smtp { background: rgba(168,85,247,.15); color: var(--purple); }

  /* ── ALERT FEED ── */
  .feed { display: flex; flex-direction: column; gap: 6px; max-height: 280px; overflow-y: auto; }
  .feed::-webkit-scrollbar { width: 3px; }
  .feed::-webkit-scrollbar-thumb { background: var(--border); border-radius: 2px; }
  .feed-item {
    display: flex; align-items: flex-start; gap: 10px;
    padding: 8px 10px; border-radius: 6px;
    background: var(--bg3); border-left: 2px solid var(--border);
    animation: slideIn .3s ease;
  }
  @keyframes slideIn { from { opacity:0; transform: translateX(-8px); } to { opacity:1; transform: none; } }
  .feed-item.ssh  { border-left-color: var(--cyan); }
  .feed-item.http { border-left-color: var(--green); }
  .feed-item.ftp  { border-left-color: var(--orange); }
  .feed-item.smtp { border-left-color: var(--purple); }
  .feed-time { font-family: var(--mono); font-size: 9px; color: var(--muted); white-space: nowrap; margin-top: 2px; }
  .feed-body { font-family: var(--mono); font-size: 11px; line-height: 1.5; }

  /* ── EMPTY STATE ── */
  .empty { text-align: center; padding: 30px; color: var(--muted); font-family: var(--mono); font-size: 12px; }

  /* ── RESPONSIVE ── */
  @media (max-width: 900px) {
    .kpi-grid { grid-template-columns: repeat(2,1fr); }
    .grid2, .grid3 { grid-template-columns: 1fr; }
  }
</style>
</head>
<body>

<header>
  <div class="logo">
    <span class="logo-icon">🍯</span>
    <div class="logo-text">
      <h1>Honeypot Control</h1>
      <p>ESGI · Projet Annuel · Sécurité Informatique</p>
    </div>
  </div>
  <div class="header-right">
    <div class="live-badge"><div class="live-dot"></div>LIVE</div>
    <div class="clock" id="clock">--:--:--</div>
  </div>
</header>

<div class="wrap">

  <!-- KPI -->
  <div class="kpi-grid">
    <div class="kpi c1">
      <div class="kpi-label">Total connexions</div>
      <div class="kpi-val" id="kpi-total">0</div>
      <div class="kpi-sub">toutes tentatives</div>
      <div class="kpi-icon">🔗</div>
    </div>
    <div class="kpi c2">
      <div class="kpi-label">IPs uniques</div>
      <div class="kpi-val" id="kpi-ips">0</div>
      <div class="kpi-sub">attaquants distincts</div>
      <div class="kpi-icon">🌐</div>
    </div>
    <div class="kpi c3">
      <div class="kpi-label">Dernière heure</div>
      <div class="kpi-val" id="kpi-hour">0</div>
      <div class="kpi-sub">activité récente</div>
      <div class="kpi-icon">⏱</div>
    </div>
    <div class="kpi c4">
      <div class="kpi-label">Commandes SSH</div>
      <div class="kpi-val" id="kpi-cmds">0</div>
      <div class="kpi-sub">exécutées dans le shell</div>
      <div class="kpi-icon">💻</div>
    </div>
  </div>

  <!-- Ligne 1 : services + chart -->
  <div class="grid2">
    <div class="panel">
      <div class="panel-title">Répartition par service</div>
      <div class="svc-list" id="svc-list">
        <div class="empty">En attente de données…</div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">Activité — 24h</div>
      <div class="chart-wrap" id="chart"></div>
    </div>
  </div>

  <!-- Ligne 2 : top IPs + top creds -->
  <div class="grid2">
    <div class="panel">
      <div class="panel-title">Top IPs attaquants</div>
      <table>
        <thead><tr><th>IP</th><th>Tentatives</th><th>Dernier contact</th></tr></thead>
        <tbody id="tbl-ips"><tr><td colspan="3" class="empty">—</td></tr></tbody>
      </table>
    </div>
    <div class="panel">
      <div class="panel-title">Top credentials essayés</div>
      <table>
        <thead><tr><th>Username</th><th>Password</th><th>Nb</th></tr></thead>
        <tbody id="tbl-creds"><tr><td colspan="3" class="empty">—</td></tr></tbody>
      </table>
    </div>
  </div>

  <!-- Ligne 3 : flux live + commandes SSH -->
  <div class="grid3">
    <div class="panel">
      <div class="panel-title">Flux d'attaques — temps réel</div>
      <div class="feed" id="feed">
        <div class="empty">En attente de connexions…</div>
      </div>
    </div>
    <div class="panel">
      <div class="panel-title">Commandes SSH capturées</div>
      <div class="feed" id="feed-cmds">
        <div class="empty">Aucune commande…</div>
      </div>
    </div>
  </div>

</div>

<script>
// ── Helpers
const $ = id => document.getElementById(id);
const esc = s => String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

function fmt_ts(ts) {
  if (!ts) return '—';
  return ts.substring(11, 19);
}

function badge(svc) {
  const s = (svc||'').toLowerCase();
  return `<span class="badge badge-${s}">${s}</span>`;
}

// ── Horloge
setInterval(() => {
  $('clock').textContent = new Date().toLocaleTimeString('fr-FR');
}, 1000);

// ── Polling principal
let prevTotal = 0;

async function refresh() {
  try {
    const res  = await fetch('/api/data');
    const data = await res.json();

    // KPI
    $('kpi-total').textContent = data.total || 0;
    $('kpi-ips').textContent   = data.unique_ips || 0;
    $('kpi-hour').textContent  = data.last_hour || 0;
    $('kpi-cmds').textContent  = data.total_cmds || 0;

    // Flash si nouvelle connexion
    if (data.total > prevTotal && prevTotal > 0) {
      $('kpi-total').style.color = '#ff4757';
      setTimeout(() => $('kpi-total').style.color = '', 600);
    }
    prevTotal = data.total;

    // Services
    const svcs = data.by_service || {};
    const maxv = Math.max(1, ...Object.values(svcs));
    const colors = { ssh:'cyan', http:'green', ftp:'orange', smtp:'purple' };
    const svcEl = $('svc-list');
    if (Object.keys(svcs).length === 0) {
      svcEl.innerHTML = '<div class="empty">Aucune connexion capturée</div>';
    } else {
      svcEl.innerHTML = Object.entries(svcs).map(([s, n]) => `
        <div class="svc-row svc-${s}">
          <div class="svc-name">${s.toUpperCase()}</div>
          <div class="svc-bar-wrap">
            <div class="svc-bar" style="width:${Math.round(n/maxv*100)}%"></div>
          </div>
          <div class="svc-cnt">${n}</div>
        </div>`).join('');
    }

    // Chart horaire
    const hourly = data.hourly || {};
    const hours  = Array.from({length:24}, (_,i) => String(i).padStart(2,'0')+':00');
    const vals   = hours.map(h => hourly[h] || 0);
    const maxH   = Math.max(1, ...vals);
    $('chart').innerHTML = hours.map((h, i) => `
      <div class="bar-col">
        <div class="bar-fill" style="height:${Math.round(vals[i]/maxH*70)+2}px" title="${h}: ${vals[i]}"></div>
        <div class="bar-label">${i%4===0 ? h.substring(0,2)+'h' : ''}</div>
      </div>`).join('');

    // Top IPs
    const ipsEl = $('tbl-ips');
    if (!data.top_ips?.length) {
      ipsEl.innerHTML = '<tr><td colspan="3" class="empty">—</td></tr>';
    } else {
      ipsEl.innerHTML = data.top_ips.map(r => `
        <tr>
          <td class="ip">${esc(r.src_ip)}</td>
          <td class="cnt">${r.cnt}</td>
          <td class="ts">${fmt_ts(r.last_seen)}</td>
        </tr>`).join('');
    }

    // Top creds
    const credsEl = $('tbl-creds');
    if (!data.top_creds?.length) {
      credsEl.innerHTML = '<tr><td colspan="3" class="empty">—</td></tr>';
    } else {
      credsEl.innerHTML = data.top_creds.map(r => `
        <tr>
          <td class="user">${esc(r.username)}</td>
          <td class="pass">${esc(r.password)}</td>
          <td class="cnt">${r.cnt}</td>
        </tr>`).join('');
    }

    // Flux live
    const feedEl = $('feed');
    if (!data.recent?.length) {
      feedEl.innerHTML = '<div class="empty">En attente de connexions…</div>';
    } else {
      feedEl.innerHTML = data.recent.map(r => {
        const svc = (r.service||'ssh').toLowerCase();
        return `
        <div class="feed-item ${svc}">
          <div class="feed-time">${fmt_ts(r.timestamp)}</div>
          <div class="feed-body">
            ${badge(r.service)}
            <span class="ip"> ${esc(r.src_ip)}</span>
            ${r.username ? `→ <span class="user">${esc(r.username)}</span> / <span class="pass">${esc(r.password)}</span>` : ''}
          </div>
        </div>`;
      }).join('');
    }

    // Commandes SSH
    const cmdEl = $('feed-cmds');
    if (!data.recent_cmds?.length) {
      cmdEl.innerHTML = '<div class="empty">Aucune commande SSH…</div>';
    } else {
      cmdEl.innerHTML = data.recent_cmds.map(r => `
        <div class="feed-item ssh">
          <div class="feed-time">${fmt_ts(r.timestamp)}</div>
          <div class="feed-body">
            <span class="ip">${esc(r.src_ip)}</span>
            <span class="cmd"> $ ${esc(r.command)}</span>
          </div>
        </div>`).join('');
    }

  } catch(e) {
    console.warn('Erreur refresh:', e);
  }
}

// Premier chargement immédiat puis toutes les 5s
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


@app.route("/")
def dashboard():
    return render_template_string(HTML)


if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════╗
║   📊 HONEYPOT DASHBOARD v1.0             ║
║   http://<IP_VM>:5000                    ║
╚══════════════════════════════════════════╝
    """)
    app.run(host="0.0.0.0", port=5000, debug=False)
