# ============================================================
#  report.py — Générateur de rapport d'analyse des logs
#  Usage : python report.py
#  Génère : reports/rapport_honeypot_YYYYMMDD.pdf
# ============================================================

import sqlite3
import os
import sys
from datetime import datetime, timedelta
from collections import defaultdict

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.gridspec import GridSpec
import matplotlib.ticker as ticker

from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Image,
    Table, TableStyle, HRFlowable, PageBreak
)

sys.path.insert(0, os.path.dirname(__file__))
from config import DB_PATH

# ── Palette
NAVY   = colors.HexColor("#050a0f")
CYAN   = colors.HexColor("#00d4ff")
GREEN  = colors.HexColor("#00ff9d")
ORANGE = colors.HexColor("#ffa502")
PURPLE = colors.HexColor("#a855f7")
RED    = colors.HexColor("#ff4757")
LGRAY  = colors.HexColor("#f0f4f8")
MGRAY  = colors.HexColor("#6b7280")
WHITE  = colors.white

SVC_COLORS = {
    "ssh":  "#00d4ff",
    "http": "#00ff9d",
    "ftp":  "#ffa502",
    "smtp": "#a855f7",
}

REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)

# ──────────────────────────────────────────────
#  Helpers DB
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
#  Collecte des données
# ──────────────────────────────────────────────

def collect_data():
    data = {}

    data["total"]      = scalar("SELECT COUNT(*) FROM connections")
    data["unique_ips"] = scalar("SELECT COUNT(DISTINCT src_ip) FROM connections")
    data["total_cmds"] = scalar("SELECT COUNT(*) FROM commands")

    # Dates min/max
    row = query("SELECT MIN(timestamp) as mn, MAX(timestamp) as mx FROM connections")
    data["date_start"] = row[0]["mn"][:10] if row and row[0]["mn"] else "—"
    data["date_end"]   = row[0]["mx"][:10] if row and row[0]["mx"] else "—"

    # Par service
    data["by_service"] = {
        r["service"]: r["cnt"]
        for r in query("SELECT service, COUNT(*) as cnt FROM connections GROUP BY service")
    }

    # Top 15 IPs
    data["top_ips"] = query("""
        SELECT src_ip, COUNT(*) as cnt, MAX(timestamp) as last_seen
        FROM connections GROUP BY src_ip ORDER BY cnt DESC LIMIT 15
    """)

    # Top 15 credentials
    data["top_creds"] = query("""
        SELECT username, password, COUNT(*) as cnt
        FROM connections WHERE username IS NOT NULL
        GROUP BY username, password ORDER BY cnt DESC LIMIT 15
    """)

    # Top usernames seuls
    data["top_users"] = query("""
        SELECT username, COUNT(*) as cnt
        FROM connections WHERE username IS NOT NULL
        GROUP BY username ORDER BY cnt DESC LIMIT 10
    """)

    # Activité par heure (toutes données)
    hourly = defaultdict(int)
    for r in query("SELECT timestamp FROM connections"):
        try:
            h = int(datetime.fromisoformat(r["timestamp"]).strftime("%H"))
            hourly[h] += 1
        except Exception:
            pass
    data["hourly"] = hourly

    # Activité par jour
    daily = defaultdict(int)
    for r in query("SELECT timestamp FROM connections"):
        try:
            d = datetime.fromisoformat(r["timestamp"]).strftime("%Y-%m-%d")
            daily[d] += 1
        except Exception:
            pass
    data["daily"] = dict(sorted(daily.items()))

    # Commandes SSH les plus fréquentes
    data["top_cmds"] = query("""
        SELECT command, COUNT(*) as cnt
        FROM commands GROUP BY command ORDER BY cnt DESC LIMIT 10
    """)

    return data

# ──────────────────────────────────────────────
#  Génération des graphiques matplotlib
# ──────────────────────────────────────────────

BG = "#050a0f"
BG2 = "#0a1520"
TEXT = "#c8e6f5"
MUTED = "#4a7a9b"

def apply_dark(ax, title=""):
    ax.set_facecolor(BG2)
    ax.tick_params(colors=MUTED, labelsize=8)
    ax.spines[:].set_color("#1a3a5c")
    if title:
        ax.set_title(title, color=TEXT, fontsize=10, pad=10, fontweight="bold")
    for label in ax.get_xticklabels() + ax.get_yticklabels():
        label.set_color(MUTED)


def fig_services(by_service, path):
    """Camembert répartition par service."""
    if not by_service:
        return None
    fig, ax = plt.subplots(figsize=(5, 4), facecolor=BG)
    labels = list(by_service.keys())
    vals   = list(by_service.values())
    clrs   = [SVC_COLORS.get(s, "#888") for s in labels]

    wedges, texts, autotexts = ax.pie(
        vals, labels=labels, colors=clrs,
        autopct="%1.1f%%", startangle=140,
        pctdistance=0.75,
        wedgeprops=dict(linewidth=2, edgecolor=BG),
    )
    for t in texts:
        t.set_color(TEXT); t.set_fontsize(9)
    for at in autotexts:
        at.set_color(BG); at.set_fontsize(8); at.set_fontweight("bold")

    ax.set_title("Répartition par service", color=TEXT, fontsize=10, fontweight="bold")
    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    return path


def fig_hourly(hourly, path):
    """Histogramme d'activité par heure."""
    fig, ax = plt.subplots(figsize=(8, 3), facecolor=BG)
    ax.set_facecolor(BG2)
    hours = list(range(24))
    vals  = [hourly.get(h, 0) for h in hours]

    bars = ax.bar(hours, vals, color="#00d4ff", alpha=0.8, width=0.7, zorder=3)
    # Gradient visuel
    for i, bar in enumerate(bars):
        bar.set_color(plt.cm.cool(i / 24))

    ax.set_xlabel("Heure de la journée", color=MUTED, fontsize=8)
    ax.set_ylabel("Connexions", color=MUTED, fontsize=8)
    ax.set_xticks(hours)
    ax.set_xticklabels([f"{h:02d}h" for h in hours], fontsize=7)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.grid(axis="y", color="#1a3a5c", linestyle="--", alpha=0.5, zorder=0)
    apply_dark(ax, "Activité par heure de la journée")

    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    return path


def fig_top_ips(top_ips, path):
    """Barres horizontales — top IPs."""
    if not top_ips:
        return None
    fig, ax = plt.subplots(figsize=(8, 4), facecolor=BG)
    ax.set_facecolor(BG2)
    ips  = [r["src_ip"] for r in top_ips[:10]][::-1]
    vals = [r["cnt"]    for r in top_ips[:10]][::-1]

    bars = ax.barh(ips, vals, color="#00d4ff", alpha=0.85, height=0.6)
    for bar, val in zip(bars, vals):
        ax.text(bar.get_width() + 0.2, bar.get_y() + bar.get_height()/2,
                str(val), va="center", ha="left", color=TEXT, fontsize=8)

    ax.set_xlabel("Nombre de tentatives", color=MUTED, fontsize=8)
    ax.grid(axis="x", color="#1a3a5c", linestyle="--", alpha=0.5)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    apply_dark(ax, "Top 10 IPs attaquantes")

    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    return path


def fig_top_users(top_users, path):
    """Barres — top usernames."""
    if not top_users:
        return None
    fig, ax = plt.subplots(figsize=(7, 3.5), facecolor=BG)
    ax.set_facecolor(BG2)
    users = [r["username"] or "(vide)" for r in top_users]
    vals  = [r["cnt"] for r in top_users]

    clrs = ["#00ff9d" if u in ("admin","root","administrator") else "#00d4ff" for u in users]
    bars = ax.bar(users, vals, color=clrs, alpha=0.85, width=0.6)
    ax.set_xticklabels(users, rotation=30, ha="right", fontsize=8)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.grid(axis="y", color="#1a3a5c", linestyle="--", alpha=0.5)
    apply_dark(ax, "Top usernames essayés")

    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    return path


def fig_daily(daily, path):
    """Courbe d'activité par jour."""
    if not daily or len(daily) < 2:
        return None
    fig, ax = plt.subplots(figsize=(8, 3), facecolor=BG)
    ax.set_facecolor(BG2)
    days = list(daily.keys())
    vals = list(daily.values())

    ax.fill_between(days, vals, alpha=0.2, color="#00d4ff")
    ax.plot(days, vals, color="#00d4ff", linewidth=2, marker="o", markersize=4)
    ax.set_xticklabels(days, rotation=30, ha="right", fontsize=7)
    ax.yaxis.set_major_locator(ticker.MaxNLocator(integer=True))
    ax.grid(color="#1a3a5c", linestyle="--", alpha=0.4)
    apply_dark(ax, "Activité par jour")

    plt.tight_layout()
    plt.savefig(path, dpi=150, bbox_inches="tight", facecolor=BG)
    plt.close()
    return path

# ──────────────────────────────────────────────
#  Construction du PDF
# ──────────────────────────────────────────────

styles = getSampleStyleSheet()

def s(name, **kw):
    st = styles[name].clone(name + "_c")
    for k, v in kw.items(): setattr(st, k, v)
    return st

S_H1   = s("Heading1", fontSize=14, textColor=CYAN,  spaceBefore=14, spaceAfter=4,  fontName="Helvetica-Bold")
S_H2   = s("Heading2", fontSize=11, textColor=colors.HexColor("#00d4ff"), spaceBefore=8, spaceAfter=3, fontName="Helvetica-Bold")
S_BODY = s("Normal",   fontSize=9,  textColor=colors.HexColor("#1f2937"), leading=14, spaceAfter=4, alignment=TA_JUSTIFY)
S_BULL = s("Normal",   fontSize=9,  textColor=colors.HexColor("#1f2937"), leading=14, leftIndent=12, spaceAfter=2)
S_MONO = s("Normal",   fontSize=8,  fontName="Courier", textColor=colors.HexColor("#374151"), leading=12)

def hr(): return HRFlowable(width="100%", thickness=1, color=CYAN, spaceAfter=6)
def sp(n=1): return Spacer(1, n * 5)
def h1(t): return [sp(), Paragraph(t, S_H1), hr()]
def h2(t): return [Paragraph(t, S_H2)]
def body(t): return Paragraph(t, S_BODY)
def bull(t): return Paragraph(f"• {t}", S_BULL)
def img(path, w=14): return Image(path, width=w*cm, height=w*0.45*cm) if path and os.path.exists(path) else sp()

def kpi_table(data):
    total = data["total"] or 0
    ips   = data["unique_ips"] or 0
    cmds  = data["total_cmds"] or 0
    svcs  = len(data["by_service"])

    def cell(label, val, col):
        return [
            Paragraph(f'<font color="{col}"><b>{val}</b></font>',
                      s("Normal", fontSize=22, alignment=TA_CENTER, fontName="Helvetica-Bold")),
            Paragraph(label, s("Normal", fontSize=8, alignment=TA_CENTER, textColor=MGRAY)),
        ]

    row = [
        cell("Connexions totales", total, "#00d4ff"),
        cell("IPs uniques",        ips,   "#00ff9d"),
        cell("Commandes SSH",      cmds,  "#ffa502"),
        cell("Services actifs",    svcs,  "#a855f7"),
    ]
    t = Table([row], colWidths=[3.8*cm]*4)
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#f8fafc")),
        ("BOX",           (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ("INNERGRID",     (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",    (0,0), (-1,-1), 12),
        ("BOTTOMPADDING", (0,0), (-1,-1), 12),
        ("ROUNDEDCORNERS",[6]),
    ]))
    return t


def tbl_ips(top_ips):
    header = [
        Paragraph("<b>IP Source</b>", s("Normal", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold")),
        Paragraph("<b>Tentatives</b>", s("Normal", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
        Paragraph("<b>Dernier contact</b>", s("Normal", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold")),
    ]
    rows = [header]
    for i, r in enumerate(top_ips[:12]):
        rows.append([
            Paragraph(r["src_ip"], S_MONO),
            Paragraph(str(r["cnt"]), s("Normal", fontSize=9, alignment=TA_CENTER, fontName="Helvetica-Bold", textColor=colors.HexColor("#ef4444"))),
            Paragraph((r["last_seen"] or "")[:19], S_MONO),
        ])
    t = Table(rows, colWidths=[5*cm, 3*cm, 7*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#0a1520")),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, colors.HexColor("#f8fafc")]),
        ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t


def tbl_creds(top_creds):
    header = [
        Paragraph("<b>Username</b>", s("Normal", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold")),
        Paragraph("<b>Password</b>", s("Normal", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold")),
        Paragraph("<b>Occurrences</b>", s("Normal", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
    ]
    rows = [header]
    for r in top_creds[:12]:
        rows.append([
            Paragraph(str(r["username"] or ""), s("Normal", fontSize=9, textColor=colors.HexColor("#059669"), fontName="Courier")),
            Paragraph(str(r["password"] or ""), s("Normal", fontSize=9, textColor=colors.HexColor("#d97706"), fontName="Courier")),
            Paragraph(str(r["cnt"]), s("Normal", fontSize=9, alignment=TA_CENTER, fontName="Helvetica-Bold", textColor=colors.HexColor("#ef4444"))),
        ])
    t = Table(rows, colWidths=[5*cm, 8*cm, 2*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#0a1520")),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, colors.HexColor("#f8fafc")]),
        ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t


def tbl_cmds(top_cmds):
    header = [
        Paragraph("<b>Commande</b>", s("Normal", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold")),
        Paragraph("<b>Fréquence</b>", s("Normal", fontSize=8, textColor=WHITE, fontName="Helvetica-Bold", alignment=TA_CENTER)),
    ]
    rows = [header]
    for r in top_cmds:
        rows.append([
            Paragraph(str(r["command"]), s("Normal", fontSize=9, fontName="Courier", textColor=colors.HexColor("#7c3aed"))),
            Paragraph(str(r["cnt"]), s("Normal", fontSize=9, alignment=TA_CENTER, fontName="Helvetica-Bold", textColor=colors.HexColor("#ef4444"))),
        ])
    t = Table(rows, colWidths=[13*cm, 2*cm])
    t.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,0),  colors.HexColor("#0a1520")),
        ("ROWBACKGROUNDS",(0,1), (-1,-1), [WHITE, colors.HexColor("#f8fafc")]),
        ("GRID",          (0,0), (-1,-1), 0.4, colors.HexColor("#e2e8f0")),
        ("TOPPADDING",    (0,0), (-1,-1), 5),
        ("BOTTOMPADDING", (0,0), (-1,-1), 5),
        ("LEFTPADDING",   (0,0), (-1,-1), 8),
        ("VALIGN",        (0,0), (-1,-1), "MIDDLE"),
    ]))
    return t


def cover(data):
    COVER_HTML = f"""
    <para align="center">
    <font name="Helvetica-Bold" size="28" color="#00d4ff">Rapport d'Analyse</font><br/>
    <font name="Helvetica-Bold" size="20" color="#ffffff">Honeypot Multi-Services</font>
    </para>"""

    cover_inner = [
        Spacer(1, 1.5*cm),
        Paragraph("🍯", s("Normal", fontSize=40, alignment=TA_CENTER)),
        Spacer(1, 0.4*cm),
        Paragraph("<b>Rapport d'Analyse</b>", s("Normal", fontSize=22, textColor=WHITE, alignment=TA_CENTER, fontName="Helvetica-Bold")),
        Paragraph("Honeypot Multi-Services", s("Normal", fontSize=14, textColor=CYAN, alignment=TA_CENTER, fontName="Helvetica-Bold")),
        Spacer(1, 0.6*cm),
        Paragraph("ESGI — Projet Annuel — Sécurité Informatique",
                  s("Normal", fontSize=10, textColor=MGRAY, alignment=TA_CENTER)),
        Spacer(1, 0.3*cm),
        Paragraph(f"Période analysée : {data['date_start']} → {data['date_end']}",
                  s("Normal", fontSize=9, textColor=MGRAY, alignment=TA_CENTER)),
        Paragraph(f"Généré le {datetime.now().strftime('%d/%m/%Y à %H:%M')}",
                  s("Normal", fontSize=9, textColor=MGRAY, alignment=TA_CENTER)),
        Spacer(1, 1.2*cm),
    ]
    ct = Table([[cover_inner]], colWidths=[15.5*cm])
    ct.setStyle(TableStyle([
        ("BACKGROUND",    (0,0), (-1,-1), colors.HexColor("#050a0f")),
        ("TOPPADDING",    (0,0), (-1,-1), 20),
        ("BOTTOMPADDING", (0,0), (-1,-1), 20),
        ("LEFTPADDING",   (0,0), (-1,-1), 30),
        ("RIGHTPADDING",  (0,0), (-1,-1), 30),
        ("ROUNDEDCORNERS",[10]),
    ]))
    return ct


# ──────────────────────────────────────────────
#  MAIN — Assemblage du rapport
# ──────────────────────────────────────────────

def generate_report():
    print("📊 Collecte des données…")
    data = collect_data()

    if data["total"] == 0:
        print("⚠  Aucune donnée dans la base. Lance le honeypot et génère du trafic d'abord !")
        print("   Tu peux tester : ssh root@localhost -p 2222")

    # ── Génération des graphiques
    print("🎨 Génération des graphiques…")
    tmp = "reports/tmp_"
    p_pie    = fig_services(data["by_service"], tmp + "pie.png")
    p_hourly = fig_hourly(data["hourly"],       tmp + "hourly.png")
    p_ips    = fig_top_ips(data["top_ips"],     tmp + "ips.png")
    p_users  = fig_top_users(data["top_users"], tmp + "users.png")
    p_daily  = fig_daily(data["daily"],         tmp + "daily.png")

    # ── Chemin du PDF de sortie
    date_str = datetime.now().strftime("%Y%m%d_%H%M")
    out_path = f"reports/rapport_honeypot_{date_str}.pdf"

    doc = SimpleDocTemplate(
        out_path, pagesize=A4,
        rightMargin=2.2*cm, leftMargin=2.2*cm,
        topMargin=2*cm, bottomMargin=2*cm,
    )

    story = []

    # ══ PAGE 1 — COUVERTURE
    story.append(sp(3))
    story.append(cover(data))
    story.append(sp(3))
    story.append(kpi_table(data))
    story.append(PageBreak())

    # ══ PAGE 2 — SYNTHÈSE
    story += h1("1. Synthèse Exécutive")
    story.append(body(
        f"Ce rapport présente l'analyse des données collectées par le honeypot multi-services "
        f"sur la période du <b>{data['date_start']}</b> au <b>{data['date_end']}</b>. "
        f"Au total, <b>{data['total']} tentatives de connexion</b> ont été enregistrées "
        f"en provenance de <b>{data['unique_ips']} adresses IP distinctes</b>, "
        f"réparties sur {len(data['by_service'])} service(s) surveillé(s)."
    ))
    story.append(sp())

    # Services actifs
    story += h2("Services surveillés")
    for svc, cnt in data["by_service"].items():
        pct = round(cnt / data["total"] * 100, 1) if data["total"] else 0
        story.append(bull(f"<b>{svc.upper()}</b> — {cnt} tentatives ({pct}%)"))
    story.append(sp())

    # Répartition graphique
    if p_pie:
        story += h2("Répartition des attaques par service")
        story.append(Image(p_pie, width=9*cm, height=7*cm))
        story.append(sp())

    # Activité journalière
    if p_daily:
        story += h2("Évolution de l'activité")
        story.append(Image(p_daily, width=15*cm, height=5.5*cm))

    story.append(PageBreak())

    # ══ PAGE 3 — ACTIVITÉ TEMPORELLE
    story += h1("2. Analyse Temporelle")
    story.append(body(
        "La distribution horaire des tentatives permet d'identifier les pics d'activité "
        "et de déterminer si les attaques sont automatisées (distribution uniforme) "
        "ou manuelles (pics concentrés)."
    ))
    story.append(sp())
    if p_hourly:
        story.append(Image(p_hourly, width=15*cm, height=5.5*cm))
    story.append(sp(2))

    # Interprétation
    if data["hourly"]:
        peak_h = max(data["hourly"], key=data["hourly"].get)
        peak_v = data["hourly"][peak_h]
        story.append(body(
            f"<b>Pic d'activité :</b> {peak_v} tentatives à {peak_h:02d}h00. "
            f"Une distribution uniforme sur 24h est typique des scanners automatisés (botnets, outils type Masscan/Shodan). "
            f"Des pics concentrés indiquent plutôt une intervention humaine."
        ))

    story.append(PageBreak())

    # ══ PAGE 4 — TOP IPs
    story += h1("3. Analyse des Sources d'Attaque")
    story.append(body(
        "Le tableau et le graphique suivants présentent les adresses IP les plus actives. "
        "Une IP avec un très grand nombre de tentatives est caractéristique d'un scanner "
        "ou d'une attaque par force brute automatisée."
    ))
    story.append(sp())

    if p_ips:
        story.append(Image(p_ips, width=15*cm, height=6*cm))
        story.append(sp())

    if data["top_ips"]:
        story.append(tbl_ips(data["top_ips"]))

    story.append(PageBreak())

    # ══ PAGE 5 — CREDENTIALS
    story += h1("4. Analyse des Credentials")
    story.append(body(
        "L'analyse des couples username/password révèle les listes de credentials "
        "utilisées par les attaquants. Les mots de passe les plus essayés correspondent "
        "typiquement aux valeurs par défaut des équipements réseau et serveurs Linux."
    ))
    story.append(sp())

    if p_users:
        story.append(Image(p_users, width=15*cm, height=6*cm))
        story.append(sp())

    story += h2("Top couples username / password")
    if data["top_creds"]:
        story.append(tbl_creds(data["top_creds"]))
    story.append(sp())

    story.append(body(
        "<b>Observation :</b> La présence massive de combinaisons triviales (admin/admin, root/root, "
        "admin/password) confirme que les attaques sont principalement automatisées et basées "
        "sur des dictionnaires standards. Cela souligne l'importance d'interdire les mots de passe "
        "par défaut et d'utiliser l'authentification par clé SSH."
    ))

    story.append(PageBreak())

    # ══ PAGE 6 — COMMANDES SSH
    story += h1("5. Analyse des Commandes SSH")
    story.append(body(
        "Une fois 'connectés' (faux succès), les attaquants exécutent des commandes "
        "de reconnaissance standard. L'analyse de ces commandes permet de comprendre "
        "leurs intentions et leur niveau de sophistication."
    ))
    story.append(sp())

    if data["top_cmds"]:
        story.append(tbl_cmds(data["top_cmds"]))
        story.append(sp(2))
        story.append(body(
            "<b>Phases d'attaque observées :</b> Les commandes se regroupent généralement en "
            "3 phases : (1) <b>Reconnaissance</b> — whoami, id, uname, hostname ; "
            "(2) <b>Recherche de données</b> — cat /etc/passwd, ls, find ; "
            "(3) <b>Persistance</b> — téléchargement de scripts, modification de crontab."
        ))
    else:
        story.append(body("Aucune commande SSH enregistrée sur cette période."))

    story.append(PageBreak())

    # ══ PAGE 7 — RECOMMANDATIONS
    story += h1("6. Recommandations de Sécurité")
    story.append(body(
        "Les données collectées par le honeypot permettent de formuler les recommandations "
        "suivantes pour durcir un système de production :"
    ))
    story.append(sp())

    recs = [
        ("<b>Désactiver l'authentification par mot de passe SSH</b>",
         "Utiliser exclusivement l'authentification par clé RSA/ED25519. "
         "Modifier dans /etc/ssh/sshd_config : PasswordAuthentication no"),
        ("<b>Changer les ports par défaut</b>",
         "Déplacer SSH sur un port non standard (ex: 2222→49152+) réduit "
         "significativement les scans automatisés."),
        ("<b>Implémenter Fail2Ban</b>",
         "Bloquer automatiquement les IPs après N tentatives échouées. "
         "Couplé au honeypot, permet un bannissement proactif."),
        ("<b>Mettre en liste noire les IPs identifiées</b>",
         f"Les {len(data['top_ips'])} IPs du rapport peuvent être bloquées via UFW ou iptables."),
        ("<b>Segmentation réseau</b>",
         "Isoler les services exposés dans une DMZ. Le honeypot doit rester "
         "dans un réseau isolé sans accès aux systèmes internes."),
        ("<b>Surveillance continue</b>",
         "Mettre en place des alertes temps réel (email/Slack) dès qu'une IP "
         "dépasse un seuil de tentatives configuré."),
    ]

    for title, desc in recs:
        story.append(bull(f"{title} : {desc}"))
        story.append(sp())

    # ══ CONCLUSION
    story += h1("7. Conclusion")
    story.append(body(
        f"Ce honeypot multi-services a permis de capturer <b>{data['total']} événements</b> "
        f"sur la période analysée. Les résultats confirment que les systèmes exposés sur "
        f"Internet sont constamment sondés par des outils automatisés, souvent en quelques "
        f"minutes après leur mise en ligne. "
        f"L'analyse des patterns d'attaque apporte une valeur opérationnelle concrète : "
        f"identification des vecteurs prioritaires, constitution de listes noires dynamiques, "
        f"et validation de l'efficacité des mesures de durcissement en place."
    ))

    # ── Build
    print("📄 Génération du PDF…")
    doc.build(story)
    print(f"✅ Rapport généré : {out_path}")

    # Nettoyage fichiers temporaires
    for p in [p_pie, p_hourly, p_ips, p_users, p_daily]:
        try:
            if p and os.path.exists(p):
                os.remove(p)
        except Exception:
            pass

    return out_path


if __name__ == "__main__":
    path = generate_report()
    print(f"\n📂 Ouvre le rapport : {path}")
