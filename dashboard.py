# ============================================================
#  dashboard.py - Console de supervision du honeypot
#  Interface web temps reel (style SIEM) - lancer separement
#  Usage : python dashboard.py  ->  http://<IP_VM>:5000
# ============================================================

import sqlite3
import os
import sys
from flask import Flask, render_template_string, jsonify
from datetime import datetime, timedelta
from collections import defaultdict

sys.path.insert(0, os.path.dirname(__file__))
from config import DB_PATH
from geoip_helper import lookup_country, country_flag

app = Flask(__name__)


def query(sql, params=()):
    if not os.path.exists(DB_PATH):
        return []
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute(sql, params)
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return rows


def scalar(sql, params=()):
    if not os.path.exists(DB_PATH):
        return 0
    conn = sqlite3.connect(DB_PATH, timeout=10)
    c = conn.cursor()
    c.execute(sql, params)
    val = c.fetchone()
    conn.close()
    return val[0] if val else 0


@app.route("/api/data")
def api_data():
    total      = scalar("SELECT COUNT(*) FROM connections")
    unique_ips = scalar("SELECT COUNT(DISTINCT src_ip) FROM connections")
    total_cmds = scalar("SELECT COUNT(*) FROM commands")
    last_hour  = scalar(
        "SELECT COUNT(*) FROM connections WHERE timestamp > ?",
        ((datetime.now() - timedelta(hours=1)).isoformat(),)
    )
    by_service = {r["service"]: r["cnt"] for r in
                  query("SELECT service, COUNT(*) as cnt FROM connections GROUP BY service")}
    top_ips = query("""
        SELECT src_ip, COUNT(*) as cnt, MAX(timestamp) as last_seen
        FROM connections GROUP BY src_ip ORDER BY cnt DESC LIMIT 8
    """)
    # Enrichissement géographique de chaque IP
    for row in top_ips:
        code, name = lookup_country(row["src_ip"])
        row["country_code"] = code
        row["country_name"] = name
        row["flag"] = country_flag(code)
    top_creds = query("""
        SELECT username, password, COUNT(*) as cnt
        FROM connections WHERE username IS NOT NULL
        GROUP BY username, password ORDER BY cnt DESC LIMIT 8
    """)
    recent = query("""
        SELECT timestamp, service, src_ip, username, password, success
        FROM connections ORDER BY id DESC LIMIT 15
    """)
    recent_cmds = query("""
        SELECT cm.timestamp, cm.command, co.src_ip
        FROM commands cm
        JOIN connections co ON cm.connection_id = co.id
        ORDER BY cm.id DESC LIMIT 10
    """)
    hourly = defaultdict(int)
    rows = query("SELECT timestamp FROM connections WHERE timestamp > ?",
                 ((datetime.now() - timedelta(hours=24)).isoformat(),))
    for r in rows:
        try:
            h = datetime.fromisoformat(r["timestamp"]).strftime("%H:00")
            hourly[h] += 1
        except Exception:
            pass
    return jsonify({
        "total": total, "unique_ips": unique_ips, "total_cmds": total_cmds,
        "last_hour": last_hour, "by_service": by_service,
        "top_ips": top_ips, "top_creds": top_creds,
        "recent": recent, "recent_cmds": recent_cmds,
        "hourly": dict(hourly),
        "generated_at": datetime.now().strftime("%H:%M:%S"),
    })


HTML = r"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Honeypot — Console de supervision</title>
<style>
  :root {
    --bg:#f5f7fa;--surface:#ffffff;--border:#e3e8ef;--border-2:#d0d7e2;
    --ink:#1c2b3a;--ink-soft:#5a6b7b;--ink-faint:#8a99a8;--accent:#2563a8;--accent-bg:#eaf1f8;
    --ssh:#2563a8;--http:#2e8b6f;--ftp:#b5740f;--smtp:#6b4fa0;--danger:#c0392b;--grid-head:#f0f3f7;
    --mono:ui-monospace,"SFMono-Regular","Menlo","Consolas",monospace;
    --sans:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
  }
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:var(--bg);color:var(--ink);font-family:var(--sans);font-size:13px;line-height:1.45}
  header{background:var(--surface);border-bottom:1px solid var(--border-2);padding:0 22px;height:52px;display:flex;align-items:center;justify-content:space-between}
  .brand{display:flex;align-items:baseline;gap:12px}
  .brand strong{font-size:15px;font-weight:600;letter-spacing:.2px}
  .brand span{font-size:11px;color:var(--ink-faint)}
  .head-right{display:flex;align-items:center;gap:18px}
  .status{display:flex;align-items:center;gap:7px;font-size:12px;color:var(--ink-soft)}
  .status .dot{width:8px;height:8px;border-radius:50%;background:var(--http)}
  .clock{font-family:var(--mono);font-size:12px;color:var(--ink-soft)}
  .layout{max-width:1440px;margin:0 auto;padding:20px 22px 48px}
  .kpis{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:18px}
  .kpi{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:16px 18px}
  .kpi .label{font-size:11px;color:var(--ink-soft);text-transform:uppercase;letter-spacing:.6px}
  .kpi .value{font-size:30px;font-weight:600;margin-top:6px;font-variant-numeric:tabular-nums}
  .kpi .meta{font-size:11px;color:var(--ink-faint);margin-top:3px}
  .kpi.accent .value{color:var(--accent)}
  .row{display:grid;gap:14px;margin-bottom:14px}
  .row.two{grid-template-columns:1fr 1fr}
  .row.split{grid-template-columns:1.6fr 1fr}
  .panel{background:var(--surface);border:1px solid var(--border);border-radius:6px;display:flex;flex-direction:column;min-height:0}
  .panel>h2{font-size:12px;font-weight:600;color:var(--ink);padding:12px 16px;border-bottom:1px solid var(--border);letter-spacing:.2px}
  .panel .body{padding:14px 16px}
  .svc{display:flex;align-items:center;gap:12px;margin-bottom:11px}
  .svc:last-child{margin-bottom:0}
  .svc .name{width:54px;font-family:var(--mono);font-size:12px;color:var(--ink-soft)}
  .svc .track{flex:1;height:18px;background:var(--bg);border:1px solid var(--border);border-radius:3px;overflow:hidden}
  .svc .fill{height:100%}
  .svc .n{width:40px;text-align:right;font-family:var(--mono);font-size:12px;font-variant-numeric:tabular-nums}
  .fill.ssh{background:var(--ssh)}.fill.http{background:var(--http)}.fill.ftp{background:var(--ftp)}.fill.smtp{background:var(--smtp)}
  .hist{display:flex;align-items:flex-end;gap:2px;height:96px}
  .hist .col{flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;height:100%;justify-content:flex-end}
  .hist .bar{width:100%;background:var(--accent);opacity:.82;border-radius:2px 2px 0 0;min-height:1px}
  .hist .h{font-size:9px;color:var(--ink-faint);font-family:var(--mono)}
  table{width:100%;border-collapse:collapse}
  thead th{font-size:10px;text-transform:uppercase;letter-spacing:.5px;color:var(--ink-soft);font-weight:600;text-align:left;padding:9px 16px;background:var(--grid-head);border-bottom:1px solid var(--border)}
  tbody td{padding:8px 16px;border-bottom:1px solid var(--border);font-size:12px}
  tbody tr:last-child td{border-bottom:none}
  tbody tr:hover{background:var(--accent-bg)}
  .mono{font-family:var(--mono)}
  .num{text-align:right;font-variant-numeric:tabular-nums;font-family:var(--mono)}
  .strong{font-weight:600}.faint{color:var(--ink-faint)}
  .tag{display:inline-block;padding:1px 7px;border-radius:3px;font-size:10px;font-weight:600;font-family:var(--mono);text-transform:uppercase;letter-spacing:.4px;border:1px solid transparent}
  .cc-badge{display:inline-block;min-width:24px;text-align:center;padding:1px 5px;margin-right:7px;border-radius:3px;font-size:10px;font-weight:700;font-family:var(--mono);color:var(--accent);background:var(--accent-bg);border:1px solid #cfe0f0;vertical-align:middle}
  .tag.ssh{color:var(--ssh);background:#eaf1f8;border-color:#cfe0f0}
  .tag.http{color:var(--http);background:#e8f4ef;border-color:#cce7db}
  .tag.ftp{color:var(--ftp);background:#f7efe0;border-color:#ecdcbd}
  .tag.smtp{color:var(--smtp);background:#efeaf6;border-color:#ddd2ec}
  .feed{max-height:320px;overflow-y:auto}
  .feed .ev{display:grid;grid-template-columns:64px auto;gap:10px;padding:7px 16px;border-bottom:1px solid var(--border);font-size:12px}
  .feed .ev:last-child{border-bottom:none}
  .feed .t{font-family:var(--mono);font-size:11px;color:var(--ink-faint)}
  .feed .d{font-family:var(--mono)}
  .feed .d .ip{color:var(--ink)}.feed .d .u{color:var(--accent)}.feed .d .p{color:var(--ftp)}.feed .d .c{color:var(--smtp)}
  .empty{padding:22px 16px;text-align:center;color:var(--ink-faint);font-size:12px}
</style>
</head>
<body>
<header>
  <div class="brand"><strong>Honeypot — Console de supervision</strong><span>ESGI · Projet annuel · Sécurité défensive</span></div>
  <div class="head-right"><div class="status"><span class="dot"></span>Collecte active</div><div class="clock" id="clock">--:--:--</div></div>
</header>
<div class="layout">
  <section class="kpis">
    <div class="kpi accent"><div class="label">Connexions totales</div><div class="value" id="k-total">0</div><div class="meta">toutes tentatives capturées</div></div>
    <div class="kpi"><div class="label">IP sources uniques</div><div class="value" id="k-ips">0</div><div class="meta">hôtes distincts observés</div></div>
    <div class="kpi"><div class="label">Dernière heure</div><div class="value" id="k-hour">0</div><div class="meta">connexions sur 60 min</div></div>
    <div class="kpi"><div class="label">Commandes shell</div><div class="value" id="k-cmds">0</div><div class="meta">saisies post-authentification</div></div>
  </section>
  <div class="row two">
    <div class="panel"><h2>Répartition par service</h2><div class="body"><div id="svc"><div class="empty">En attente de données</div></div></div></div>
    <div class="panel"><h2>Activité sur 24 heures</h2><div class="body"><div class="hist" id="hist"></div></div></div>
  </div>
  <div class="row two">
    <div class="panel"><h2>IP sources les plus actives</h2><table><thead><tr><th>Adresse IP</th><th>Pays</th><th class="num">Tentatives</th><th>Dernier contact</th></tr></thead><tbody id="t-ips"><tr><td colspan="4" class="empty">Aucune donnée</td></tr></tbody></table></div>
    <div class="panel"><h2>Identifiants les plus tentés</h2><table><thead><tr><th>Utilisateur</th><th>Mot de passe</th><th class="num">Occurrences</th></tr></thead><tbody id="t-creds"><tr><td colspan="3" class="empty">Aucune donnée</td></tr></tbody></table></div>
  </div>
  <div class="row split">
    <div class="panel"><h2>Flux d'événements en temps réel</h2><div class="feed" id="feed"><div class="empty">En attente de connexions</div></div></div>
    <div class="panel"><h2>Commandes shell capturées</h2><div class="feed" id="feed-cmds"><div class="empty">Aucune commande</div></div></div>
  </div>
</div>
<script>
const $ = id => document.getElementById(id);
const esc = s => String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
const hhmmss = ts => ts ? ts.substring(11,19) : '—';
const SVC = ['ssh','http','ftp','smtp'];
setInterval(() => { $('clock').textContent = new Date().toLocaleTimeString('fr-FR'); }, 1000);
async function refresh() {
  try {
    const data = await (await fetch('/api/data')).json();
    $('k-total').textContent = data.total || 0;
    $('k-ips').textContent   = data.unique_ips || 0;
    $('k-hour').textContent  = data.last_hour || 0;
    $('k-cmds').textContent  = data.total_cmds || 0;
    const svcs = data.by_service || {};
    const max = Math.max(1, ...Object.values(svcs));
    const el = $('svc');
    const keys = Object.keys(svcs);
    el.innerHTML = keys.length ? SVC.filter(s=>svcs[s]).map(s=>`<div class="svc"><span class="name">${s.toUpperCase()}</span><span class="track"><span class="fill ${s}" style="width:${Math.round(svcs[s]/max*100)}%"></span></span><span class="n">${svcs[s]}</span></div>`).join('') : '<div class="empty">Aucune connexion capturÃ©e</div>';
    const hourly = data.hourly || {};
    const hours = Array.from({length:24}, (_,i)=>String(i).padStart(2,'0')+':00');
    const vals = hours.map(h => hourly[h] || 0);
    const mh = Math.max(1, ...vals);
    $('hist').innerHTML = hours.map((h,i)=>`<div class="col"><div class="bar" style="height:${Math.round(vals[i]/mh*100)}%" title="${h} — ${vals[i]} conn."></div><div class="h">${i%4===0 ? h.substring(0,2) : ''}</div></div>`).join('');
    const ips = $('t-ips');
    ips.innerHTML = (data.top_ips&&data.top_ips.length) ? data.top_ips.map(r=>{
      const cc = (r.country_code||'').toLowerCase();
      const ccu = esc(r.country_code||'');
      const flag = cc ? `<img src="https://flagcdn.com/20x15/${cc}.png" width="20" height="15" alt="" onerror="this.replaceWith(Object.assign(document.createElement('span'),{className:'cc-badge',textContent:'${ccu}'}))" style="vertical-align:middle;margin-right:7px;border-radius:2px;box-shadow:0 0 1px rgba(0,0,0,.4)">` : '';
      return `<tr><td class="mono strong">${esc(r.src_ip)}</td><td>${flag}${esc(r.country_name||'—')}</td><td class="num">${r.cnt}</td><td class="faint mono">${hhmmss(r.last_seen)}</td></tr>`;
    }).join('') : '<tr><td colspan="4" class="empty">Aucune donnée</td></tr>';
    const cr = $('t-creds');
    cr.innerHTML = (data.top_creds&&data.top_creds.length) ? data.top_creds.map(r=>`<tr><td class="mono">${esc(r.username)}</td><td class="mono">${esc(r.password)}</td><td class="num">${r.cnt}</td></tr>`).join('') : '<tr><td colspan="3" class="empty">Aucune donnée</td></tr>';
    const f = $('feed');
    f.innerHTML = (data.recent&&data.recent.length) ? data.recent.map(r=>{const s=(r.service||'ssh').toLowerCase();return `<div class="ev"><span class="t">${hhmmss(r.timestamp)}</span><span class="d"><span class="tag ${s}">${s}</span> <span class="ip">${esc(r.src_ip)}</span>${r.username?` &rarr; <span class="u">${esc(r.username)}</span> / <span class="p">${esc(r.password)}</span>`:''}</span></div>`;}).join('') : '<div class="empty">En attente de connexions</div>';
    const fc = $('feed-cmds');
    fc.innerHTML = (data.recent_cmds&&data.recent_cmds.length) ? data.recent_cmds.map(r=>`<div class="ev"><span class="t">${hhmmss(r.timestamp)}</span><span class="d"><span class="ip">${esc(r.src_ip)}</span> <span class="c">$ ${esc(r.command)}</span></span></div>`).join('') : '<div class="empty">Aucune commande</div>';
  } catch(e) { console.warn('refresh', e); }
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>"""


@app.route("/")
def dashboard():
    return render_template_string(HTML)


if __name__ == "__main__":
    print("Honeypot dashboard -> http://0.0.0.0:5000")
    app.run(host="0.0.0.0", port=5000, debug=False)
