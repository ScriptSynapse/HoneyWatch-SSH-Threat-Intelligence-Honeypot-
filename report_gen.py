"""
report_gen.py — Generates professional PDF threat intelligence reports.
Uses reportlab to produce a styled multi-page report from the SQLite database.
"""

import io
import json
import logging
from datetime import datetime, timezone, timedelta
from pathlib import Path

from reportlab.lib               import colors
from reportlab.lib.pagesizes     import A4
from reportlab.lib.styles        import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units         import mm, cm
from reportlab.lib.enums         import TA_LEFT, TA_CENTER, TA_RIGHT
from reportlab.platypus          import (SimpleDocTemplate, Paragraph, Spacer,
                                          Table, TableStyle, PageBreak,
                                          HRFlowable, KeepTogether)
from reportlab.platypus.flowables import Flowable
from reportlab.graphics.shapes   import Drawing, Rect, String, Line, Polygon
from reportlab.graphics.charts.barcharts  import VerticalBarChart
from reportlab.graphics.charts.piecharts  import Pie
from reportlab.graphics          import renderPDF

import database as db

log = logging.getLogger("honeypot.report")

# ── Brand palette ─────────────────────────────────────────────────────────────
C_BG        = colors.HexColor("#04080d")
C_PANEL     = colors.HexColor("#0c1620")
C_GREEN     = colors.HexColor("#00ffa3")
C_RED       = colors.HexColor("#ff2d55")
C_AMBER     = colors.HexColor("#ffcc00")
C_CYAN      = colors.HexColor("#00ccff")
C_PURPLE    = colors.HexColor("#b060ff")
C_ORANGE    = colors.HexColor("#ff6600")
C_TXT       = colors.HexColor("#a8c4d8")
C_TXT2      = colors.HexColor("#567890")
C_BORDER    = colors.HexColor("#1e3245")
C_WHITE     = colors.white
C_BLACK     = colors.black

SEVERITY_COLORS = {
    "critical": C_RED,
    "high":     C_ORANGE,
    "medium":   C_AMBER,
    "low":      C_GREEN,
}

PAGE_W, PAGE_H = A4
MARGIN = 18 * mm
CONTENT_W = PAGE_W - 2 * MARGIN


# ── Custom Flowables ──────────────────────────────────────────────────────────

class ColorBar(Flowable):
    """Full-width colored horizontal bar — used as section headers."""
    def __init__(self, text, bg_color=C_PANEL, text_color=C_GREEN,
                 height=10*mm, font_size=11):
        super().__init__()
        self.text       = text
        self.bg_color   = bg_color
        self.text_color = text_color
        self.bar_height = height
        self.font_size  = font_size

    def wrap(self, aw, ah):
        self._aw = aw
        return aw, self.bar_height

    def draw(self):
        c = self.canv
        c.setFillColor(self.bg_color)
        c.rect(0, 0, self._aw, self.bar_height, fill=1, stroke=0)
        # left accent line
        c.setFillColor(self.text_color)
        c.rect(0, 0, 3, self.bar_height, fill=1, stroke=0)
        c.setFillColor(self.text_color)
        c.setFont("Helvetica-Bold", self.font_size)
        c.drawString(8, self.bar_height / 2 - self.font_size / 3, self.text.upper())


class StatBox(Flowable):
    """Single KPI box with label + big number."""
    def __init__(self, label, value, sub="", color=C_GREEN, w=40*mm, h=22*mm):
        super().__init__()
        self.label = label
        self.value = str(value)
        self.sub   = sub
        self.color = color
        self.box_w = w
        self.box_h = h

    def wrap(self, aw, ah):
        return self.box_w, self.box_h

    def draw(self):
        c = self.canv
        # Background
        c.setFillColor(C_PANEL)
        c.roundRect(0, 0, self.box_w, self.box_h, 3, fill=1, stroke=0)
        # Bottom accent bar
        c.setFillColor(self.color)
        c.rect(0, 0, self.box_w, 2, fill=1, stroke=0)
        # Label
        c.setFillColor(C_TXT2)
        c.setFont("Helvetica", 6)
        c.drawString(5, self.box_h - 9, self.label.upper())
        # Value
        font_size = 18 if len(self.value) < 8 else 14
        c.setFillColor(self.color)
        c.setFont("Helvetica-Bold", font_size)
        c.drawString(5, self.box_h / 2 - font_size / 3, self.value)
        # Sub
        if self.sub:
            c.setFillColor(C_TXT2)
            c.setFont("Helvetica", 6.5)
            c.drawString(5, 6, self.sub)


def stat_row(stats_list):
    """Build a Table of StatBox flowables in a single row."""
    n = len(stats_list)
    w = (CONTENT_W - (n - 1) * 3*mm) / n
    boxes = [[StatBox(lbl, val, sub, col, w=w) for lbl, val, sub, col in stats_list]]
    t = Table(boxes, colWidths=[w] * n, rowHeights=[22*mm])
    t.setStyle(TableStyle([("LEFTPADDING", (0,0), (-1,-1), 0),
                           ("RIGHTPADDING", (0,0), (-1,-1), 3),
                           ("TOPPADDING", (0,0), (-1,-1), 0),
                           ("BOTTOMPADDING", (0,0), (-1,-1), 0)]))
    return t


# ── Styles ────────────────────────────────────────────────────────────────────

def _styles():
    base = getSampleStyleSheet()
    def s(name, **kw):
        return ParagraphStyle(name, parent=base["Normal"], **kw)
    return {
        "title":    s("RTitle", fontSize=26, textColor=C_GREEN, fontName="Helvetica-Bold",
                       spaceAfter=2, alignment=TA_CENTER),
        "subtitle": s("RSub", fontSize=11, textColor=C_TXT2, fontName="Helvetica",
                       alignment=TA_CENTER, spaceAfter=4),
        "h2":       s("RH2", fontSize=10, textColor=C_CYAN, fontName="Helvetica-Bold",
                       spaceBefore=6, spaceAfter=3),
        "body":     s("RBody", fontSize=8.5, textColor=C_TXT, fontName="Helvetica",
                       leading=13, spaceAfter=4),
        "mono":     s("RMono", fontSize=7.5, textColor=C_GREEN, fontName="Courier",
                       leading=11, spaceAfter=2),
        "caption":  s("RCap", fontSize=7, textColor=C_TXT2, fontName="Helvetica",
                       alignment=TA_CENTER),
        "label":    s("RLbl", fontSize=7.5, textColor=C_TXT2, fontName="Helvetica",
                       spaceAfter=1),
        "tag_red":  s("RTagR", fontSize=7, textColor=C_RED, fontName="Helvetica-Bold",
                       alignment=TA_CENTER),
        "tag_y":    s("RTagY", fontSize=7, textColor=C_AMBER, fontName="Helvetica-Bold",
                       alignment=TA_CENTER),
        "tag_g":    s("RTagG", fontSize=7, textColor=C_GREEN, fontName="Helvetica-Bold",
                       alignment=TA_CENTER),
    }


# ── Table helpers ─────────────────────────────────────────────────────────────

def dark_table(headers, rows, col_widths, row_colors=None):
    data    = [headers] + rows
    n_cols  = len(headers)
    n_rows  = len(data)

    style = [
        # Header row
        ("BACKGROUND",   (0,0), (-1,0),  C_PANEL),
        ("TEXTCOLOR",    (0,0), (-1,0),  C_CYAN),
        ("FONTNAME",     (0,0), (-1,0),  "Helvetica-Bold"),
        ("FONTSIZE",     (0,0), (-1,0),  7),
        ("TOPPADDING",   (0,0), (-1,0),  4),
        ("BOTTOMPADDING",(0,0), (-1,0),  4),
        # Body rows
        ("BACKGROUND",   (0,1), (-1,-1), C_BG),
        ("TEXTCOLOR",    (0,1), (-1,-1), C_TXT),
        ("FONTNAME",     (0,1), (-1,-1), "Helvetica"),
        ("FONTSIZE",     (0,1), (-1,-1), 7),
        ("TOPPADDING",   (0,1), (-1,-1), 3),
        ("BOTTOMPADDING",(0,1), (-1,-1), 3),
        ("LEFTPADDING",  (0,0), (-1,-1), 5),
        ("RIGHTPADDING", (0,0), (-1,-1), 5),
        ("ROWBACKGROUNDS",(0,1),(-1,-1), [C_BG, C_PANEL]),
        ("GRID",         (0,0), (-1,-1), 0.3, C_BORDER),
    ]
    if row_colors:
        for row_idx, color in row_colors:
            style.append(("TEXTCOLOR", (0, row_idx+1), (-1, row_idx+1), color))

    t = Table(data, colWidths=col_widths)
    t.setStyle(TableStyle(style))
    return t


# ── Bar chart (reportlab native) ─────────────────────────────────────────────

def mini_bar_chart(labels, values, bar_color=C_CYAN, w=CONTENT_W, h=55*mm):
    drawing = Drawing(w, h)
    bc = VerticalBarChart()
    bc.x         = 30
    bc.y         = 20
    bc.width     = w - 40
    bc.height    = h - 30
    bc.data      = [values]
    bc.categoryAxis.categoryNames = labels
    bc.categoryAxis.labels.fontName  = "Helvetica"
    bc.categoryAxis.labels.fontSize  = 6.5
    bc.categoryAxis.labels.angle     = 30
    bc.categoryAxis.labels.fillColor = C_TXT2
    bc.valueAxis.labels.fontName     = "Helvetica"
    bc.valueAxis.labels.fontSize     = 6.5
    bc.valueAxis.labels.fillColor    = C_TXT2
    bc.valueAxis.strokeColor         = C_BORDER
    bc.categoryAxis.strokeColor      = C_BORDER
    bc.bars[0].fillColor             = bar_color
    bc.bars[0].strokeColor           = None
    drawing.add(bc)
    # Background rect
    bg = Rect(0, 0, w, h, fillColor=C_PANEL, strokeColor=C_BORDER, strokeWidth=0.5)
    drawing.insert(0, bg)
    return drawing


def mini_pie_chart(labels, values, palette=None, w=70*mm, h=60*mm):
    if palette is None:
        palette = [C_RED, C_ORANGE, C_AMBER, C_GREEN, C_CYAN, C_PURPLE]
    drawing = Drawing(w, h)
    pie = Pie()
    pie.x       = int(w/2) - 20
    pie.y       = int(h/2) - 20
    pie.width   = 40
    pie.height  = 40
    pie.data    = values
    pie.labels  = [f"{l} ({v})" for l, v in zip(labels, values)]
    pie.simpleLabels = False
    for i, c in enumerate(palette[:len(values)]):
        pie.slices[i].fillColor     = c
        pie.slices[i].strokeColor   = C_BG
        pie.slices[i].strokeWidth   = 1
        pie.slices[i].labelRadius   = 1.25
        pie.slices[i].fontSize      = 5.5
        pie.slices[i].fontColor     = C_TXT
    drawing.add(pie)
    return drawing


# ── Page template (header/footer) ────────────────────────────────────────────

def _page_header_footer(canvas, doc):
    canvas.saveState()
    w, h = A4
    # Top bar
    canvas.setFillColor(C_PANEL)
    canvas.rect(0, h - 14*mm, w, 14*mm, fill=1, stroke=0)
    canvas.setFillColor(C_GREEN)
    canvas.rect(0, h - 14*mm, 4, 14*mm, fill=1, stroke=0)
    canvas.setFillColor(C_GREEN)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(MARGIN, h - 9*mm, "🍯 HONEYWATCH")
    canvas.setFillColor(C_TXT2)
    canvas.setFont("Helvetica", 7)
    canvas.drawRightString(w - MARGIN, h - 9*mm,
                           "SSH THREAT INTELLIGENCE REPORT  //  CONFIDENTIAL")
    # Bottom bar
    canvas.setFillColor(C_PANEL)
    canvas.rect(0, 0, w, 10*mm, fill=1, stroke=0)
    canvas.setFillColor(C_TXT2)
    canvas.setFont("Helvetica", 6.5)
    canvas.drawString(MARGIN, 3.5*mm, f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    canvas.drawCentredString(w/2, 3.5*mm, "CONFIDENTIAL — FOR AUTHORIZED PERSONNEL ONLY")
    canvas.drawRightString(w - MARGIN, 3.5*mm, f"Page {doc.page}")
    canvas.restoreState()


# ── Main report builder ───────────────────────────────────────────────────────

def generate_report(output_path: str = "reports/honeywatch_report.pdf",
                    days: int = 14) -> str:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    ST  = _styles()
    now = datetime.now(timezone.utc)
    cutoff = (now - timedelta(days=days)).isoformat()

    # ── Pull all data ──────────────────────────────────────────────────────────
    total_attempts  = db.scalar("SELECT COUNT(*) FROM auth_attempts WHERE timestamp>?", (cutoff,))
    total_successes = db.scalar("SELECT COUNT(*) FROM auth_attempts WHERE timestamp>? AND result='accepted'", (cutoff,))
    unique_ips      = db.scalar("SELECT COUNT(DISTINCT peer_ip) FROM auth_attempts WHERE timestamp>?", (cutoff,))
    total_commands  = db.scalar("SELECT COUNT(*) FROM commands WHERE timestamp>?", (cutoff,))
    suspicious_cnt  = db.scalar("SELECT COUNT(*) FROM suspicious_events WHERE timestamp>?", (cutoff,))
    malware_cnt     = db.scalar("SELECT COUNT(*) FROM malware_captures WHERE timestamp>?", (cutoff,))
    critical_cnt    = db.scalar("SELECT COUNT(*) FROM suspicious_events WHERE timestamp>? AND severity='critical'", (cutoff,))
    success_rate    = round(total_successes / max(total_attempts, 1) * 100, 1)

    top_users = db.query("SELECT username as v, COUNT(*) c FROM auth_attempts WHERE timestamp>? GROUP BY username ORDER BY c DESC LIMIT 12", (cutoff,))
    top_pass  = db.query("SELECT password as v, COUNT(*) c FROM auth_attempts WHERE timestamp>? GROUP BY password ORDER BY c DESC LIMIT 12", (cutoff,))
    top_ips   = db.query("""
        SELECT a.peer_ip, COUNT(*) c, r.country, r.city, r.isp, r.abuse_score
        FROM auth_attempts a LEFT JOIN ip_reputation r ON a.peer_ip=r.ip
        WHERE a.timestamp>? GROUP BY a.peer_ip ORDER BY c DESC LIMIT 15
    """, (cutoff,))
    top_countries = db.query("""
        SELECT r.country, COUNT(*) c
        FROM auth_attempts a JOIN ip_reputation r ON a.peer_ip=r.ip
        WHERE a.timestamp>? GROUP BY r.country ORDER BY c DESC LIMIT 8
    """, (cutoff,))
    attack_types  = db.query("SELECT attack_type as v, COUNT(*) c FROM auth_attempts WHERE timestamp>? AND attack_type IS NOT NULL GROUP BY attack_type ORDER BY c DESC", (cutoff,))
    top_cmds      = db.query("SELECT command_base as v, COUNT(*) c FROM commands WHERE timestamp>? AND command_base!='' GROUP BY command_base ORDER BY c DESC LIMIT 12", (cutoff,))
    susp_types    = db.query("SELECT suspicious_type as v, COUNT(*) c FROM suspicious_events WHERE timestamp>? GROUP BY suspicious_type ORDER BY c DESC", (cutoff,))
    recent_susp   = db.query("""
        SELECT s.timestamp, s.peer_ip, s.suspicious_type, s.severity, s.detail, r.country
        FROM suspicious_events s LEFT JOIN ip_reputation r ON s.peer_ip=r.ip
        WHERE s.timestamp>? ORDER BY s.timestamp DESC LIMIT 20
    """, (cutoff,))
    malware_rows  = db.query("SELECT timestamp, peer_ip, url, tool, filename, file_hash FROM malware_captures WHERE timestamp>? ORDER BY timestamp DESC LIMIT 10", (cutoff,))

    # Daily timeline
    timeline = []
    for i in range(days-1, -1, -1):
        d = (now - timedelta(days=i)).strftime("%Y-%m-%d")
        cnt = db.scalar("SELECT COUNT(*) FROM auth_attempts WHERE timestamp LIKE ?", (d+"%",))
        timeline.append((d[-5:], cnt))   # MM-DD format for chart

    # ── Build story ────────────────────────────────────────────────────────────
    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        leftMargin=MARGIN, rightMargin=MARGIN,
        topMargin=16*mm, bottomMargin=12*mm,
        title="HoneyWatch Threat Intelligence Report",
        author="HoneyWatch Platform",
    )
    story = []

    # ── Cover page ─────────────────────────────────────────────────────────────
    story.append(Spacer(1, 30*mm))
    story.append(Paragraph("HONEYWATCH", ST["title"]))
    story.append(Paragraph("SSH Threat Intelligence Report", ST["subtitle"]))
    story.append(Spacer(1, 4*mm))
    story.append(HRFlowable(width=CONTENT_W, thickness=0.5, color=C_BORDER))
    story.append(Spacer(1, 4*mm))
    period_str = f"{(now-timedelta(days=days)).strftime('%d %b %Y')} — {now.strftime('%d %b %Y')}"
    story.append(Paragraph(f"Reporting Period: {period_str}", ST["subtitle"]))
    story.append(Paragraph(f"Generated: {now.strftime('%Y-%m-%d %H:%M UTC')}", ST["subtitle"]))
    story.append(Spacer(1, 10*mm))

    # Executive KPI row
    story.append(stat_row([
        ("Total Attempts",   f"{total_attempts:,}", f"in {days} days",  C_CYAN),
        ("Unique Attackers", f"{unique_ips:,}",     "distinct IPs",     C_GREEN),
        ("Logins Accepted",  f"{total_successes:,}",f"{success_rate}%", C_RED),
        ("Critical Events",  f"{critical_cnt:,}",   "severity: critical", C_RED),
    ]))
    story.append(Spacer(1, 3*mm))
    story.append(stat_row([
        ("Commands Logged",  f"{total_commands:,}", "post-auth",        C_AMBER),
        ("Suspicious Events",f"{suspicious_cnt:,}", "flagged",          C_ORANGE),
        ("Malware Captures", f"{malware_cnt:,}",    "files downloaded", C_PURPLE),
        ("Avg Attempts/Day", f"{total_attempts//max(days,1):,}", "rate", C_CYAN),
    ]))
    story.append(PageBreak())

    # ── Section 1: Attack Timeline ─────────────────────────────────────────────
    story.append(ColorBar("01 — Attack Timeline"))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        f"The following chart shows daily authentication attempts over the {days}-day reporting period. "
        "Spikes indicate automated botnet campaigns or coordinated brute-force attacks.",
        ST["body"]))
    story.append(Spacer(1, 2*mm))

    tl_labels = [t[0] for t in timeline]
    tl_values = [t[1] for t in timeline]
    story.append(mini_bar_chart(tl_labels, tl_values, bar_color=C_CYAN, h=60*mm))
    story.append(Spacer(1, 4*mm))

    # ── Section 2: Top Attackers ───────────────────────────────────────────────
    story.append(ColorBar("02 — Top Attacking IPs"))
    story.append(Spacer(1, 3*mm))

    ip_rows = []
    for i, row in enumerate(top_ips):
        score = row.get("abuse_score") or 0
        score_str = f"{score}/100"
        severity_col = C_RED if score >= 80 else C_AMBER if score >= 50 else C_GREEN
        ip_rows.append([
            str(i+1),
            row["peer_ip"] or "—",
            row.get("country") or "Unknown",
            row.get("city") or "—",
            row.get("isp") or "—",
            f"{row['c']:,}",
            score_str,
        ])

    story.append(dark_table(
        ["#", "IP Address", "Country", "City", "ISP", "Attempts", "Abuse Score"],
        ip_rows,
        col_widths=[8*mm, 28*mm, 28*mm, 22*mm, 45*mm, 18*mm, 18*mm],
        row_colors=[(i, C_RED if (r.get("abuse_score") or 0) >= 80 else
                      C_AMBER if (r.get("abuse_score") or 0) >= 50 else C_TXT)
                    for i, r in enumerate(top_ips)],
    ))
    story.append(Spacer(1, 4*mm))

    # Country breakdown + pie side by side
    story.append(ColorBar("03 — Geographic Distribution"))
    story.append(Spacer(1, 3*mm))

    if top_countries:
        country_labels  = [r["country"] or "Unknown" for r in top_countries]
        country_values  = [r["c"] for r in top_countries]
        country_pct     = [round(v/max(sum(country_values),1)*100, 1) for v in country_values]

        country_rows = [[r["country"] or "Unknown",
                         f"{r['c']:,}",
                         f"{p}%"] for r, p in zip(top_countries, country_pct)]

        tbl = dark_table(["Country", "Attempts", "Share"],
                         country_rows,
                         col_widths=[60*mm, 30*mm, 25*mm])
        palette = [C_RED, C_ORANGE, C_AMBER, C_CYAN, C_GREEN, C_PURPLE,
                   C_TXT2, C_TXT2]
        pie = mini_pie_chart(country_labels[:6], country_values[:6],
                             palette=palette, w=75*mm, h=55*mm)

        combo = Table([[tbl, pie]],
                      colWidths=[CONTENT_W - 78*mm, 78*mm])
        combo.setStyle(TableStyle([
            ("VALIGN", (0,0), (-1,-1), "TOP"),
            ("LEFTPADDING",  (0,0), (-1,-1), 0),
            ("RIGHTPADDING", (0,0), (-1,-1), 0),
        ]))
        story.append(combo)
    story.append(Spacer(1, 4*mm))

    # ── Section 4: Credentials ─────────────────────────────────────────────────
    story.append(ColorBar("04 — Credential Analysis"))
    story.append(Spacer(1, 3*mm))

    cred_data_u = [[r["v"], f"{r['c']:,}"] for r in top_users]
    cred_data_p = [[repr(r["v"]) if not r["v"] else r["v"], f"{r['c']:,}"] for r in top_pass]

    cred_u = dark_table(["Username", "Attempts"], cred_data_u,
                        col_widths=[55*mm, 22*mm])
    cred_p = dark_table(["Password", "Attempts"], cred_data_p,
                        col_widths=[55*mm, 22*mm])
    combo = Table([[cred_u, Spacer(6*mm, 1), cred_p]],
                  colWidths=[77*mm, 6*mm, 77*mm])
    combo.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"TOP"),
                               ("LEFTPADDING",(0,0),(-1,-1),0),
                               ("RIGHTPADDING",(0,0),(-1,-1),0)]))
    story.append(combo)
    story.append(Spacer(1, 3*mm))

    # Attack types
    if attack_types:
        story.append(ColorBar("05 — Attack Classification"))
        story.append(Spacer(1, 3*mm))
        at_rows = [[r["v"].replace("_"," ").title(), f"{r['c']:,}",
                    f"{round(r['c']/max(total_attempts,1)*100,1)}%"]
                   for r in attack_types]
        story.append(dark_table(["Attack Pattern", "Count", "Share"],
                                at_rows, col_widths=[80*mm, 30*mm, 30*mm]))
        story.append(Spacer(1, 4*mm))

    # ── Section 6: Commands ────────────────────────────────────────────────────
    story.append(PageBreak())
    story.append(ColorBar("06 — Post-Auth Command Analysis"))
    story.append(Spacer(1, 3*mm))
    story.append(Paragraph(
        "Commands executed by attackers after successful authentication, revealing their intent and tooling.",
        ST["body"]))
    story.append(Spacer(1, 2*mm))

    if top_cmds:
        cmd_labels = [r["v"] for r in top_cmds]
        cmd_values = [r["c"] for r in top_cmds]
        story.append(mini_bar_chart(cmd_labels, cmd_values, bar_color=C_GREEN, h=55*mm))
        story.append(Spacer(1, 3*mm))

    # ── Section 7: Suspicious Events ──────────────────────────────────────────
    story.append(ColorBar("07 — Threat Events"))
    story.append(Spacer(1, 3*mm))

    if recent_susp:
        susp_rows = []
        for r in recent_susp:
            detail = ""
            try:
                detail = json.loads(r.get("detail") or "{}").get("command", "")[:50]
            except Exception:
                pass
            sev = r.get("severity", "medium")
            susp_rows.append([
                r["timestamp"][:16].replace("T", " "),
                r["peer_ip"] or "—",
                r.get("country") or "—",
                r["suspicious_type"].replace("_"," "),
                sev.upper(),
                detail,
            ])
        sev_row_colors = []
        for i, r in enumerate(recent_susp):
            sev = r.get("severity","medium")
            sev_row_colors.append((i, SEVERITY_COLORS.get(sev, C_TXT)))

        story.append(dark_table(
            ["Timestamp", "IP", "Country", "Event Type", "Severity", "Detail"],
            susp_rows,
            col_widths=[28*mm, 24*mm, 20*mm, 30*mm, 16*mm, 42*mm],
            row_colors=sev_row_colors,
        ))
        story.append(Spacer(1, 4*mm))

    # ── Section 8: Malware Captures ────────────────────────────────────────────
    if malware_rows:
        story.append(ColorBar("08 — Malware Captures", bg_color=colors.HexColor("#1a0010")))
        story.append(Spacer(1, 3*mm))
        story.append(Paragraph(
            "Files fetched by attackers during honeypot sessions. Each entry represents a real "
            "payload download attempt captured and hashed by the honeypot.",
            ST["body"]))
        story.append(Spacer(1, 2*mm))
        mal_rows = [[
            r["timestamp"][:16].replace("T"," "),
            r["peer_ip"] or "—",
            r.get("tool") or "—",
            (r.get("url") or "")[:45],
            r.get("filename") or "—",
            (r.get("file_hash") or "")[:20] + "…",
        ] for r in malware_rows]
        story.append(dark_table(
            ["Timestamp", "Attacker IP", "Tool", "URL", "Filename", "SHA256 (prefix)"],
            mal_rows,
            col_widths=[26*mm, 22*mm, 12*mm, 45*mm, 20*mm, 35*mm],
        ))
        story.append(Spacer(1, 4*mm))

    # ── Section 9: Recommendations ────────────────────────────────────────────
    story.append(ColorBar("09 — Security Recommendations"))
    story.append(Spacer(1, 3*mm))

    recs = [
        ("Disable Password Authentication",
         "Replace SSH password auth with key-based authentication. "
         "This eliminates 100% of password brute-force attacks immediately. "
         "Edit /etc/ssh/sshd_config: set PasswordAuthentication no."),
        ("Change Default Credentials Immediately",
         f"'{top_users[0]['v'] if top_users else 'root'}' is the most-attempted username. "
         "Ensure no service accounts use default or common passwords. "
         f"Top attacked password was '{top_pass[0]['v'] if top_pass else 'blank'}'."),
        ("Implement IP Reputation Blocking",
         f"{sum(1 for r in top_ips if (r.get('abuse_score') or 0) >= 80)} of the top {len(top_ips)} "
         "attacking IPs have AbuseIPDB scores above 80. Integrate a blocklist feed "
         "such as AbuseIPDB or Emerging Threats to proactively block known-bad IPs."),
        ("Network Segmentation & Egress Filtering",
         "Attackers consistently attempt outbound connections to download payloads "
         "and enroll in botnets. Block all unexpected outbound traffic — especially "
         "to non-business IPs on ports 80/443."),
        ("Monitor Cron and Startup Scripts",
         f"{sum(1 for r in recent_susp if 'persistence' in (r.get('suspicious_type') or ''))} "
         "persistence attempts detected. Implement integrity monitoring on "
         "/etc/cron*, /var/spool/cron, /etc/rc.local, and systemd unit files."),
        ("Deploy Fail2Ban or Similar Tarpitting",
         "A simple rate-limiter or tarpitting mechanism (adding artificial auth delays) "
         "significantly degrades automated brute-force tools. Recommended: "
         "fail2ban with a 3-attempt / 300-second rule on sshd."),
    ]

    for i, (title, body) in enumerate(recs):
        story.append(KeepTogether([
            Paragraph(f"R{i+1:02d} — {title}", ST["h2"]),
            Paragraph(body, ST["body"]),
            Spacer(1, 2*mm),
        ]))

    # ── Appendix: raw top-10 credential pairs ─────────────────────────────────
    story.append(PageBreak())
    story.append(ColorBar("Appendix — Top Credential Pairs Observed"))
    story.append(Spacer(1, 3*mm))
    pairs = db.query("""
        SELECT username, password, COUNT(*) c
        FROM auth_attempts WHERE timestamp>?
        GROUP BY username, password ORDER BY c DESC LIMIT 20
    """, (cutoff,))
    pair_rows = [[r["username"], repr(r["password"]) if not r["password"] else r["password"],
                  f"{r['c']:,}"] for r in pairs]
    story.append(dark_table(["Username", "Password", "Count"],
                            pair_rows, col_widths=[50*mm, 80*mm, 30*mm]))
    story.append(Spacer(1, 6*mm))
    story.append(Paragraph(
        "This report was automatically generated by HoneyWatch — SSH Threat Intelligence Platform. "
        "Data collected from a monitored honeypot environment. "
        "For questions contact your security team.",
        ST["label"]))

    # ── Build PDF ──────────────────────────────────────────────────────────────
    doc.build(story, onFirstPage=_page_header_footer,
              onLaterPages=_page_header_footer)
    log.info("📄 PDF report generated: %s", output_path)
    return output_path


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    db.init_db()
    out = sys.argv[1] if len(sys.argv) > 1 else "reports/honeywatch_report.pdf"
    days = int(sys.argv[2]) if len(sys.argv) > 2 else 14
    path = generate_report(out, days)
    print(f"Report saved to: {path}")
