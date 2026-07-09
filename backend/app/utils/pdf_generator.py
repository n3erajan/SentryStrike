"""
Sentry Strike - Professional Penetration Test Report Generator
Converts scan JSON output into a polished, client-ready PDF report.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.lib.utils import ImageReader
from reportlab.platypus import (
    BaseDocTemplate,
    Flowable,
    Frame,
    HRFlowable,
    Image,
    KeepTogether,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


def _fmt_dt(value, fmt="%Y-%m-%d %H:%M:%S") -> str:
    """Safely format a datetime object or ISO string to a readable string."""
    if value is None:
        return "N/A"
    if hasattr(value, "strftime"):          # actual datetime / date object
        return value.strftime(fmt)
    try:
        return datetime.fromisoformat(str(value)).strftime(fmt)
    except Exception:
        return str(value)[:19]


def _para_escape(value: Any) -> str:
    """Escape dynamic text before passing it to ReportLab Paragraph markup."""
    text = "N/A" if value is None else str(value)
    return escape(text).replace("\n", "<br/>")


def _dedupe_semicolon_text(value: Any) -> str:
    text = str(value or "").strip()
    parts = re.split(
        r"(?:;\s*|\n)(?=(?:"
        r"(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s+https?://|"
        r"Header not found:|Supporting finding:|Payload |Form |"
        r"Authentication |SQL-engine |Response |Missing |Sensitive |Insecure "
        r"))",
        text,
    )
    cleaned: list[str] = []
    seen: set[str] = set()
    seen_excerpts: set[str] = set()
    for part in parts:
        normalized = " ".join(part.split())
        normalized = _collapse_repeated_evidence_excerpt(normalized)
        excerpt_key = _evidence_excerpt_key(normalized)
        if excerpt_key and any(excerpt_key in existing or existing in excerpt_key for existing in seen_excerpts):
            continue
        if excerpt_key:
            seen_excerpts.add(excerpt_key)
        key = normalized.lower()
        if normalized and key not in seen:
            seen.add(key)
            cleaned.append(normalized)
    return "\n".join(cleaned)


def _evidence_excerpt_key(text: str) -> str | None:
    excerpt_match = re.search(r'Excerpt:\s*([\'"])(?P<excerpt>.*?)(?:\1|$)', text, re.I)
    if not excerpt_match:
        return None
    excerpt = re.sub(r"\s+", " ", excerpt_match.group("excerpt")).strip().lower()
    if "you have an error in your sql syntax" in excerpt and (
        "mysql server version" in excerpt or "mariadb server version" in excerpt
    ):
        return "mysql_sql_syntax_verbose_error"
    if "sqlstate" in excerpt:
        return "sqlstate_verbose_error"
    if len(excerpt) < 40:
        return None
    return excerpt


def _collapse_repeated_evidence_excerpt(text: str) -> str:
    excerpt_match = re.search(r'Excerpt:\s*([\'"])(?P<excerpt>.*?)(?:\1|$)', text, re.I)
    if not excerpt_match:
        return text
    excerpt = " ".join(excerpt_match.group("excerpt").split()).lower()
    if not excerpt:
        return text
    # When merged evidence contains the same proof excerpt twice, keep the
    # highest-signal first record and drop later near-duplicates.
    records = re.split(r";\s+(?=(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s+https?://)", text)
    if len(records) <= 1:
        return text
    kept: list[str] = []
    seen_excerpts: set[str] = set()
    for record in records:
        match = re.search(r'Excerpt:\s*([\'"])(?P<excerpt>.*?)(?:\1|$)', record, re.I)
        if match:
            key = " ".join(match.group("excerpt").split()).lower()
            if any(key in existing or existing in key for existing in seen_excerpts):
                continue
            seen_excerpts.add(key)
        kept.append(record)
    return "; ".join(kept)

OWASP_CATEGORY_LABELS = {
    "a01": "A01-Broken Access Control",
    "a02": "A02-Security Misconfiguration",
    "a03": "A03-Software Supply Chain Failures",
    "a04": "A04-Cryptographic Failures",
    "a05": "A05-Injection",
    "a06": "A06-Insecure Design",
    "a07": "A07-Authentication Failures",
    "a08": "A08-Software and Data Integrity Failures",
    "a09": "A09-Security Logging and Monitoring Failures",
    "a10": "A10-Mishandling of Exceptional Conditions",
}


def _clean_enum(value: Any, *, title_case: bool = True) -> str:
    """Return enum values without Python enum class prefixes."""
    if value is None:
        return "N/A"
    if hasattr(value, "value"):
        value = value.value
    text = str(value)
    if "." in text:
        text = text.split(".")[-1]
    if not text:
        return "N/A"
    return text.replace("_", " ").title() if title_case else text


def _clean_category(value: Any) -> str:
    if value is None:
        return "N/A"
    if hasattr(value, "value"):
        return str(value.value)
    text = str(value)
    key = text.split(".")[-1].lower()
    return OWASP_CATEGORY_LABELS.get(key, text)


def _clean_status(value: Any) -> str:
    return _clean_enum(value).replace("Needs Review", "Needs Review")


# ─────────────────────────────── Palette ────────────────────────────────── #
#
# Design principles:
#   • All text-on-background combos meet WCAG AA (≥4.5:1 normal, ≥3:1 large/bold)
#   • Severity header bars use deep solid fills → white text always legible
#   • Severity text colors on white all ≥5.8:1 contrast ratio
#   • Labels use #444C56 (~8.5:1) instead of the former #8B949E (3.4:1, failing AA)
#   • Yellow/amber never used as text on white - replaced with deep amber-brown
#   • Row tints are very pale; all text printed on them stays near-black

# ── Structural neutrals ──────────────────────────────────────────────────
DARK_BG      = colors.HexColor("#1A1F2E")   # cover / header bars (deep navy)
PANEL_BG     = colors.HexColor("#252B3B")   # secondary dark panel
LIGHT_BG     = colors.HexColor("#F3F4F6")   # alternating table row tint
DIVIDER      = colors.HexColor("#C8CDD5")   # rule lines
WHITE        = colors.white
BODY_TEXT    = colors.HexColor("#1C2128")   # primary body  (contrast ~16:1 on white)
LABEL_TEXT   = colors.HexColor("#444C56")   # field labels  (contrast ~8.5:1 on white ✓)
CAPTION_TEXT = colors.HexColor("#57606A")   # captions/meta (contrast ~5.7:1 on white ✓)

# ── Brand ─────────────────────────────────────────────────────────────────
BRAND_RED    = colors.HexColor("#C0392B")   # Sentry Strike red  (7.1:1 on white ✓)
BRAND_RED_LT = colors.HexColor("#FDECEA")   # faint red tint

# ── Severity foreground - text/badge color ON WHITE background ────────────
#   Critical  #B91C1C  7.2:1 ✓   High   #C2410C  5.8:1 ✓
#   Medium    #92400E  6.7:1 ✓   Low    #1D4ED8  7.1:1 ✓  
SEV_FG = {
    "Critical": colors.HexColor("#B91C1C"),
    "High":     colors.HexColor("#C2410C"),
    "Medium":   colors.HexColor("#92400E"),
    "Low":      colors.HexColor("#1D4ED8"),
    "Info":     colors.HexColor("#57606A"),
}

# ── Severity solid fills - ONLY used as bar/badge backgrounds with WHITE text ─
SEV_COLOR = {
    "Critical": colors.HexColor("#991B1B"),   # deep crimson
    "High":     colors.HexColor("#9A3412"),   # deep burnt-orange
    "Medium":   colors.HexColor("#78350F"),   # deep amber-brown
    "Low":      colors.HexColor("#1E3A8A"),   # deep royal blue
    "Info":     colors.HexColor("#4B5563"),
}

# ── Severity row tints - very pale, near-black text printed on top ─────────
SEV_BG = {
    "Critical": colors.HexColor("#FEF2F2"),
    "High":     colors.HexColor("#FFF7ED"),
    "Medium":   colors.HexColor("#FFFBEB"),
    "Low":      colors.HexColor("#EFF6FF"),
    "Info":     colors.HexColor("#F9FAFB"),
}

# Legacy aliases so all existing references keep working
ACCENT_RED    = BRAND_RED
ACCENT_ORANGE = SEV_FG["High"]
ACCENT_YELLOW = SEV_FG["Medium"]
ACCENT_BLUE   = SEV_FG["Low"]
MID_GRAY      = CAPTION_TEXT


# ─────────────────────────── Custom Flowables ───────────────────────────── #

class ColoredBar(Flowable):
    """A full-width colored rectangle - used for section divider bars."""

    def __init__(self, color, height=3, width=None):
        super().__init__()
        self._color = color
        self._height = height
        self._width = width

    def wrap(self, avail_w, avail_h):
        self.width = self._width or avail_w
        self.height = self._height
        return self.width, self.height

    def draw(self):
        self.canv.setFillColor(self._color)
        self.canv.rect(0, 0, self.width, self.height, fill=1, stroke=0)


class SeverityBadge(Flowable):
    """Pill-shaped severity badge."""

    def __init__(self, severity: str, font_size=8):
        super().__init__()
        self._sev = severity
        self._fs = font_size
        self.width = 70
        self.height = 16

    def wrap(self, *_):
        return self.width, self.height

    def draw(self):
        c = self.canv
        color = SEV_COLOR.get(self._sev, MID_GRAY)
        bg    = SEV_BG.get(self._sev, LIGHT_BG)
        r = self.height / 2
        c.setFillColor(bg)
        c.setStrokeColor(color)
        c.setLineWidth(0.8)
        c.roundRect(0, 0, self.width, self.height, r, fill=1, stroke=1)
        c.setFillColor(color)
        c.setFont("Helvetica-Bold", self._fs)
        c.drawCentredString(self.width / 2, 4, self._sev.upper())


class CodeBlock(Flowable):
    """Width-aware monospace block that wraps long tokens inside its bounds."""

    def __init__(self, text: str, *, font_name="Courier", font_size=7.2, leading=9.4):
        super().__init__()
        self.text = self._normalize_text(text)
        self.font_name = font_name
        self.font_size = font_size
        self.leading = leading
        self.pad_x = 5
        self.pad_y = 4
        self.lines: list[str] = []

    @staticmethod
    def _normalize_text(text: str) -> str:
        cleaned = str(text or "").replace("\t", "    ")
        cleaned = re.sub(r"</?pre[^>]*>", "", cleaned, flags=re.I)
        cleaned = re.sub(r"</?code[^>]*>", "", cleaned, flags=re.I)
        return cleaned

    def _string_width(self, text: str) -> float:
        from reportlab.pdfbase.pdfmetrics import stringWidth

        return stringWidth(text, self.font_name, self.font_size)

    def _wrap_line(self, line: str, max_width: float) -> list[str]:
        if not line:
            return [""]

        wrapped: list[str] = []
        remaining = line.replace("\t", "    ")
        while remaining:
            if self._string_width(remaining) <= max_width:
                wrapped.append(remaining)
                break

            lo, hi = 1, len(remaining)
            best = 1
            while lo <= hi:
                mid = (lo + hi) // 2
                if self._string_width(remaining[:mid]) <= max_width:
                    best = mid
                    lo = mid + 1
                else:
                    hi = mid - 1

            break_at = best
            space_at = remaining.rfind(" ", 0, best + 1)
            if space_at > max(12, int(best * 0.55)):
                break_at = space_at

            chunk = remaining[:break_at].rstrip()
            wrapped.append(chunk or remaining[:best])
            remaining = remaining[break_at:].lstrip() if break_at == space_at else remaining[break_at:]

        return wrapped

    def _wrap_text(self, avail_w: float) -> list[str]:
        max_text_width = max(20, avail_w - (self.pad_x * 2))
        lines: list[str] = []
        for raw_line in self.text.splitlines() or [""]:
            lines.extend(self._wrap_line(raw_line, max_text_width))
        return lines

    def wrap(self, avail_w, avail_h):
        self.width = avail_w
        self.lines = self._wrap_text(avail_w)
        self.height = (self.pad_y * 2) + max(1, len(self.lines)) * self.leading
        return self.width, self.height

    def split(self, avail_w, avail_h):
        lines = self._wrap_text(avail_w)
        max_lines = int(max(0, avail_h - (self.pad_y * 2)) // self.leading)
        if max_lines <= 1 or len(lines) <= max_lines:
            return []

        first = CodeBlock("\n".join(lines[:max_lines]), font_name=self.font_name, font_size=self.font_size, leading=self.leading)
        rest = CodeBlock("\n".join(lines[max_lines:]), font_name=self.font_name, font_size=self.font_size, leading=self.leading)
        return [first, rest]

    def draw(self):
        c = self.canv
        c.saveState()
        c.setFillColor(LIGHT_BG)
        c.roundRect(0, 0, self.width, self.height, 2, fill=1, stroke=0)
        c.setFillColor(BODY_TEXT)
        c.setFont(self.font_name, self.font_size)

        y = self.height - self.pad_y - self.font_size
        for line in self.lines:
            c.drawString(self.pad_x, y, line)
            y -= self.leading
        c.restoreState()


class CoverPage:
    """Draws the full dark cover page directly onto a canvas."""

    @staticmethod
    def draw(canvas, doc, report_data: dict):
        w, h = A4
        data = report_data.get("data", {})
        stats = data.get("statistics", {})
        target_url = data.get("scan_id", "")
        # Try to get URL from first vulnerability
        vulns = data.get("vulnerabilities", [])
        target = "http://192.168.16.101/dvwa/"
        if vulns:
            target = vulns[0].get("location", {}).get("url", target)
            target = "/".join(target.split("/")[:3])

        gen_at = data.get("generated_at", "")
        date_str = _fmt_dt(gen_at, "%B %d, %Y")

        canvas.saveState()

        # ── Dark background ──
        canvas.setFillColor(DARK_BG)
        canvas.rect(0, 0, w, h, fill=1, stroke=0)

        # ── Red accent strip (left edge) ──
        canvas.setFillColor(BRAND_RED)
        canvas.rect(0, 0, 6*mm, h, fill=1, stroke=0)

        # ── Logo / tool name ──
        canvas.setFillColor(BRAND_RED)
        canvas.setFont("Helvetica-Bold", 13)
        canvas.drawString(22*mm, h - 28*mm, "SENTRY STRIKE")
        canvas.setFillColor(MID_GRAY)
        canvas.setFont("Helvetica", 9)
        canvas.drawString(22*mm, h - 34*mm, "Web Application Security Scanner")

        # ── Divider line ──
        canvas.setStrokeColor(colors.HexColor("#30363D"))
        canvas.setLineWidth(0.5)
        canvas.line(22*mm, h - 37*mm, w - 20*mm, h - 37*mm)

        # ── Main title ──
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 34)
        canvas.drawString(22*mm, h - 60*mm, "Penetration Test")
        canvas.setFont("Helvetica-Bold", 34)
        canvas.drawString(22*mm, h - 74*mm, "Report")

        canvas.setFillColor(MID_GRAY)
        canvas.setFont("Helvetica", 11)
        canvas.drawString(22*mm, h - 85*mm, f"Target: {target}")
        canvas.drawString(22*mm, h - 92*mm, f"Date:   {date_str}")
        scan_id_str = f"Scan ID: {data.get('scan_id', 'N/A')}"
        # Clip long scan IDs to fit within page margin
        canvas.setFont("Helvetica", 10)
        max_w = w - 44*mm
        while canvas.stringWidth(scan_id_str, "Helvetica", 10) > max_w and len(scan_id_str) > 20:
            scan_id_str = scan_id_str[:-4] + "…"
        canvas.drawString(22*mm, h - 99*mm, scan_id_str)

        # ── Risk score pill ──
        risk = data.get("risk_score", 0)
        pill_x, pill_y, pill_w, pill_h = 22*mm, h - 130*mm, 55*mm, 28*mm
        canvas.setFillColor(ACCENT_RED)
        canvas.roundRect(pill_x, pill_y, pill_w, pill_h, 5, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 20)
        canvas.drawCentredString(pill_x + pill_w/2, pill_y + 14, f"{risk:.1f}")
        canvas.setFont("Helvetica-Bold", 7)
        canvas.drawCentredString(pill_x + pill_w/2, pill_y + 5, "RISK SCORE / 100")

        # ── Stats boxes ──
        sev_order = [
            ("Critical", ACCENT_RED,    stats.get("severity_breakdown", {}).get("critical", 0)),
            ("High",     ACCENT_ORANGE, stats.get("severity_breakdown", {}).get("high", 0)),
            ("Medium",   ACCENT_YELLOW, stats.get("severity_breakdown", {}).get("medium", 0)),
            ("Low",      ACCENT_BLUE,   stats.get("severity_breakdown", {}).get("low", 0)),
        ]
        bx = 85*mm
        for label, clr, count in sev_order:
            canvas.setFillColor(clr)
            canvas.roundRect(bx, pill_y, 22*mm, pill_h, 4, fill=1, stroke=0)
            canvas.setFillColor(WHITE)
            canvas.setFont("Helvetica-Bold", 16)
            canvas.drawCentredString(bx + 11*mm, pill_y + 14, str(count))
            canvas.setFont("Helvetica-Bold", 6.5)
            canvas.drawCentredString(bx + 11*mm, pill_y + 5, label.upper())
            bx += 26*mm

        # ── Total vulns ──
        canvas.setFillColor(PANEL_BG)
        canvas.roundRect(22*mm, h - 160*mm, 55*mm, 20*mm, 4, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 15)
        canvas.drawCentredString(49.5*mm, h - 151*mm, str(stats.get("total_vulnerabilities", 0)))
        canvas.setFont("Helvetica-Bold", 7)
        canvas.drawCentredString(49.5*mm, h - 158*mm, "TOTAL VULNERABILITIES")

        canvas.setFillColor(PANEL_BG)
        canvas.roundRect(85*mm, h - 160*mm, 55*mm, 20*mm, 4, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 15)
        canvas.drawCentredString(112.5*mm, h - 151*mm, str(stats.get("total_urls_crawled", 0)))
        canvas.setFont("Helvetica-Bold", 7)
        canvas.drawCentredString(112.5*mm, h - 158*mm, "URLS CRAWLED")

        # ── Footer ──
        canvas.setFillColor(colors.HexColor("#30363D"))
        canvas.rect(0, 0, w, 18*mm, fill=1, stroke=0)
        canvas.setFillColor(MID_GRAY)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(22*mm, 11*mm, "CONFIDENTIAL - For authorized recipient use only")
        canvas.drawRightString(w - 20*mm, 11*mm, "OWASP Top 10 2025")
        canvas.setStrokeColor(BRAND_RED)
        canvas.setLineWidth(1)
        canvas.line(0, 18*mm, w, 18*mm)

        canvas.restoreState()


# ──────────────────────────── Style Registry ────────────────────────────── #

def build_styles():
    base = getSampleStyleSheet()

    def s(name, **kw) -> ParagraphStyle:
        return ParagraphStyle(name, **kw)

    return {
        "h1": s("H1",
            fontName="Helvetica-Bold", fontSize=18, textColor=BODY_TEXT,
            spaceAfter=4, spaceBefore=14, leading=22),
        "h2": s("H2",
            fontName="Helvetica-Bold", fontSize=13, textColor=BRAND_RED,
            spaceAfter=3, spaceBefore=10, leading=16),
        "h3": s("H3",
            fontName="Helvetica-Bold", fontSize=10, textColor=BODY_TEXT,
            spaceAfter=2, spaceBefore=6, leading=13),
        "body": s("Body",
            fontName="Helvetica", fontSize=9.5, textColor=BODY_TEXT,
            leading=14, spaceAfter=4, alignment=TA_JUSTIFY),
        "body_sm": s("BodySm",
            fontName="Helvetica", fontSize=8.5, textColor=BODY_TEXT,
            leading=12, spaceAfter=3),
        "body_sm_justify": s("BodySmJustify",
            fontName="Helvetica", fontSize=8.5, textColor=BODY_TEXT,
            leading=12, spaceAfter=3, alignment=TA_JUSTIFY),
        "label": s("Label",
            fontName="Helvetica-Bold", fontSize=8, textColor=LABEL_TEXT,
            leading=10, spaceAfter=3, spaceBefore=7),
        "mono": s("Mono",
            fontName="Courier", fontSize=7.5, textColor=BODY_TEXT,
            leading=10, spaceAfter=2, alignment=TA_LEFT,
            wordWrap="CJK", splitLongWords=1,
            backColor=LIGHT_BG, borderPadding=(3, 5, 3, 5)),
        "caption": s("Caption",
            fontName="Helvetica-Oblique", fontSize=8, textColor=CAPTION_TEXT,
            leading=10, spaceAfter=6),
        "toc_entry": s("TOC",
            fontName="Helvetica", fontSize=10, textColor=BODY_TEXT,
            leading=16, spaceAfter=0),
        "toc_title": s("TOCTitle",
            fontName="Helvetica-Bold", fontSize=10, textColor=BODY_TEXT,
            leading=16, spaceAfter=0),
        "center": s("Center",
            fontName="Helvetica", fontSize=9, textColor=BODY_TEXT,
            alignment=TA_CENTER, leading=28),
        # ── Used for Paragraph cells that sit on DARK_BG table headers ──────
        "th": s("TH",
            fontName="Helvetica-Bold", fontSize=9, textColor=WHITE,
            leading=12, spaceAfter=0),
        "th_center": s("THCenter",
            fontName="Helvetica-Bold", fontSize=9, textColor=WHITE,
            alignment=TA_CENTER, leading=12, spaceAfter=0),
    }


# ──────────────────────────── Page Templates ────────────────────────────── #

def make_doc(buf: BytesIO, report_data: dict) -> BaseDocTemplate:
    doc = BaseDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=22*mm, bottomMargin=22*mm,
        title="Sentry Strike - Penetration Test Report",
        author="Sentry Strike Scanner",
    )

    def draw_cover(canvas, doc):
        CoverPage.draw(canvas, doc, report_data)

    def header_footer(canvas, doc):
        w, h = A4
        canvas.saveState()
        # Top bar
        canvas.setFillColor(DARK_BG)
        canvas.rect(0, h - 14*mm, w, 14*mm, fill=1, stroke=0)
        canvas.setFillColor(BRAND_RED)
        canvas.rect(0, h - 14*mm, 5*mm, 14*mm, fill=1, stroke=0)
        canvas.setFillColor(WHITE)
        canvas.setFont("Helvetica-Bold", 8)
        canvas.drawString(10*mm, h - 9*mm, "SENTRY STRIKE")
        canvas.setFillColor(MID_GRAY)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawRightString(w - 10*mm, h - 9*mm, "Penetration Test Report - CONFIDENTIAL")

        # Bottom bar
        canvas.setFillColor(LIGHT_BG)
        canvas.rect(0, 0, w, 14*mm, fill=1, stroke=0)
        canvas.setStrokeColor(DIVIDER)
        canvas.setLineWidth(0.5)
        canvas.line(0, 14*mm, w, 14*mm)
        canvas.setFillColor(MID_GRAY)
        canvas.setFont("Helvetica", 7.5)
        canvas.drawString(20*mm, 5*mm, "© Sentry Strike Security Report - For Authorized Use Only")
        canvas.drawRightString(w - 20*mm, 5*mm, f"Page {doc.page}")

        canvas.restoreState()

    cover_frame = Frame(0, 0, A4[0], A4[1], leftPadding=0, rightPadding=0,
                        topPadding=0, bottomPadding=0, id="cover")
    body_frame  = Frame(20*mm, 22*mm, A4[0] - 40*mm, A4[1] - 44*mm,
                        leftPadding=0, rightPadding=0,
                        topPadding=0, bottomPadding=0, id="body")

    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame], onPage=draw_cover),
        PageTemplate(id="Normal", frames=[body_frame], onPage=header_footer),
    ])
    return doc


# ─────────────────────────── Helper builders ────────────────────────────── #

def section_header(title: str, styles: dict, number: str = "") -> list:
    """Returns flowables for a styled section heading."""
    prefix = f"{number}. " if number else ""
    elems = [
        Spacer(1, 4*mm),
        ColoredBar(BRAND_RED, height=3),
        Spacer(1, 2*mm),
        Paragraph(f"{prefix}{title}", styles["h1"]),
        Spacer(1, 1*mm),
    ]
    return elems


def sub_header(title: str, styles: dict) -> list:
    return [
        Spacer(1, 3*mm),
        Paragraph(title, styles["h2"]),
        HRFlowable(width="100%", thickness=0.5, color=DIVIDER, spaceAfter=2),
    ]


def labeled_value(label: str, value: str, styles: dict) -> list:
    return [
        Paragraph(label.upper(), styles["label"]),
        Paragraph(_para_escape(value), styles["body_sm"]),
    ]


def code_block(text: str, styles: dict) -> Flowable:
    return full_code_block(text, styles)


def severity_row_color(sev: str):
    return SEV_BG.get(sev, WHITE)


def full_code_block(text: str, styles: dict) -> Flowable:
    return CodeBlock(text)


def _report_metadata_value(d: dict, key: str) -> Any:
    metadata = d.get("report_metadata") or {}
    return d.get(key) or metadata.get(key) or {}


def _display_value(value: Any) -> str:
    if isinstance(value, bool):
        return "Yes" if value else "No"
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def _metric_table(rows: list[tuple[str, Any]], styles: dict, *, value_width: float = 32*mm) -> Table:
    table_rows = [[Paragraph("Metric", styles["th"]), Paragraph("Value", styles["th_center"])]]
    for label, value in rows:
        table_rows.append([
            Paragraph(_para_escape(label), styles["body_sm"]),
            Paragraph(_para_escape(_display_value(value)), styles["body_sm"]),
        ])

    tbl = Table(table_rows, colWidths=[None, value_width])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR",  (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
        ("GRID",       (0, 0), (-1, -1), 0.4, DIVIDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ("VALIGN",     (0, 0), (-1, -1), "TOP"),
    ]))
    return tbl


def _response_evidence_label_and_text(resp: str) -> tuple[str, str]:
    text = str(resp or "").strip()
    evidence_prefix = "VERIFICATION EVIDENCE:"
    excerpt_prefix = "RESPONSE EXCERPT:"
    if text.startswith(evidence_prefix) and excerpt_prefix not in text:
        return "VERIFICATION EVIDENCE", _dedupe_semicolon_text(text[len(evidence_prefix):])
    return "RESPONSE SNIPPET", text


def _split_response_evidence(resp: str) -> tuple[str | None, str | None]:
    text = str(resp or "").strip()
    evidence_prefix = "VERIFICATION EVIDENCE:"
    excerpt_prefix = "RESPONSE EXCERPT:"
    if not text.startswith(evidence_prefix):
        return None, text or None
    remainder = text[len(evidence_prefix):].strip()
    if excerpt_prefix not in remainder:
        return _dedupe_semicolon_text(remainder), None
    evidence_text, excerpt = remainder.split(excerpt_prefix, 1)
    return _dedupe_semicolon_text(evidence_text), excerpt.strip() or None


# ─────────────────────────── Report Sections ────────────────────────────── #

def build_toc(data: dict, styles: dict) -> list:
    elems = section_header("Table of Contents", styles, "")
    rows = [
        ("1.", "Executive Summary"),
        ("2.", "Scan Statistics"),
        ("3.", "Technology Detected"),
        ("4.", "Vulnerability Summary"),
        ("5.", "Detailed Findings"),
        ("6.", "Remediation Roadmap"),
    ]
    tbl_data = [[Paragraph(n, styles["toc_title"]), Paragraph(t, styles["toc_entry"])] for n, t in rows]
    tbl = Table(tbl_data, colWidths=[15*mm, None])
    tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [WHITE, LIGHT_BG]),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("LINEBELOW", (0, -1), (-1, -1), 0.5, DIVIDER),
    ]))
    elems.append(tbl)
    return elems


def build_executive_summary(data: dict, styles: dict) -> list:
    d = data.get("data", {})
    elems = section_header("Executive Summary", styles, "1")

    summary = d.get("executive_summary", "No summary available.")
    elems.append(Paragraph(_para_escape(summary), styles["body"]))
    elems.append(Spacer(1, 4*mm))

    # Key metadata box
    gen_at = d.get("generated_at", "")
    date_str = _fmt_dt(gen_at, "%B %d, %Y %H:%M UTC")

    vulns = d.get("vulnerabilities", [])
    target = "N/A"
    if vulns:
        url = vulns[0].get("location", {}).get("url", "")
        target = "/".join(url.split("/")[:3]) if url else "N/A"

    meta_rows = [
        ["Scan Target",  target],
        ["Scan ID",      d.get("scan_id", "N/A")],
        ["Submitted By", d.get("owner_email") or d.get("owner_user_id") or "N/A"],
        ["Authorization Confirmed", "Yes" if (d.get("authorization") or {}).get("confirmed") else "No"],
        ["Authorization Confirmed At", _fmt_dt((d.get("authorization") or {}).get("confirmed_at"))],
        ["Generated At", date_str],
        ["Risk Score",   f"{d.get('risk_score', 0):.2f} / 100" + (f" ({d.get('risk_level')})" if d.get('risk_level') else "")],
        ["Classification", "CONFIDENTIAL"],
    ]
    tbl = Table(
        [[Paragraph(f"<b>{r[0]}</b>", styles["body_sm"]),
          Paragraph(_para_escape(r[1]), styles["body_sm"])] for r in meta_rows],
        colWidths=[45*mm, None],
    )
    tbl.setStyle(TableStyle([
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [LIGHT_BG, WHITE]),
        ("GRID", (0, 0), (-1, -1), 0.4, DIVIDER),
        ("TOPPADDING",  (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
    ]))
    elems.append(tbl)
    return elems


def build_statistics(data: dict, styles: dict) -> list:
    d = data.get("data", {})
    stats = d.get("statistics", {})
    sev   = stats.get("severity_breakdown", {})
    elems = section_header("Scan Statistics", styles, "2")

    # Top-level numbers
    top_data = [
        ["Total URLs Crawled", "Total Vulnerabilities", "Risk Score"],
        [
            Paragraph(f'<font size="22"><b>{stats.get("total_urls_crawled", 0)}</b></font>', styles["center"]),
            Paragraph(f'<font size="22"><b>{stats.get("total_vulnerabilities", 0)}</b></font>', styles["center"]),
            Paragraph(f'<font size="22"><b>{d.get("risk_score", 0):.1f}</b></font>', styles["center"]),
        ],
    ]
    top_tbl = Table(top_data, colWidths=[56.5*mm, 56.5*mm, 57*mm])
    top_tbl.setStyle(TableStyle([
        ("BACKGROUND",   (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR",    (0, 0), (-1, 0), WHITE),
        ("FONTNAME",     (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE",     (0, 0), (-1, 0), 9),
        ("ALIGN",        (0, 0), (-1, -1), "CENTER"),
        ("VALIGN",       (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING",   (0, 0), (-1, 0), 8),
        ("BOTTOMPADDING",(0, 0), (-1, 0), 8),
        ("TOPPADDING",   (0, 1), (-1, 1), 12),
        ("BOTTOMPADDING",(0, 1), (-1, 1), 12),
        ("GRID",         (0, 0), (-1, -1), 0.5, DIVIDER),
        ("LINEABOVE",    (0, 0), (-1, 0),  2,   BRAND_RED),
    ]))
    elems.append(top_tbl)
    elems.append(Spacer(1, 5*mm))

    # Severity breakdown
    elems += sub_header("Severity Breakdown", styles)
    sev_rows = [
        [Paragraph("Severity", styles["th"]),
         Paragraph("Count", styles["th"]),
         Paragraph("Visual", styles["th"]),
         Paragraph("% of Total", styles["th"])],
    ]
    total = stats.get("total_vulnerabilities", 1) or 1
    for sev_label, sev_key in [("Critical", "critical"), ("High", "high"),
                                ("Medium", "medium"), ("Low", "low"), ("Info", "info")]:
        count = sev.get(sev_key, 0)
        pct = count / total * 100
        bar_len = max(int(pct * 0.8), 0)  # max ~80 chars
        bar = "█" * bar_len
        fg = SEV_FG.get(sev_label, LABEL_TEXT)      # contrast-safe text color on white
        sev_rows.append([
            Paragraph(f'<font color="#{fg.hexval()[2:]}"><b>{sev_label}</b></font>', styles["body_sm"]),
            Paragraph(f"<b>{count}</b>", styles["body_sm"]),
            Paragraph(f'<font color="#{fg.hexval()[2:]}">{bar}</font>', styles["body_sm"]),
            Paragraph(f"{pct:.1f}%", styles["body_sm"]),
        ])

    sev_tbl = Table(sev_rows, colWidths=[28*mm, 18*mm, None, 22*mm])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR",  (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
        ("GRID",       (0, 0), (-1, -1), 0.4, DIVIDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    elems.append(sev_tbl)

    # Category breakdown
    elems.append(Spacer(1, 5*mm))
    elems += sub_header("Findings by OWASP Category", styles)
    vulns = d.get("vulnerabilities", [])
    cat_counts: dict[str, int] = {}
    for v in vulns:
        cat = _clean_category(v.get("category", "Unknown"))
        cat_counts[cat] = cat_counts.get(cat, 0) + 1

    cat_rows = [[Paragraph("OWASP Category", styles["th"]),
                 Paragraph("Count", styles["th_center"])]]
    for cat, cnt in sorted(cat_counts.items(), key=lambda x: -x[1]):
        cat_rows.append([Paragraph(_para_escape(cat), styles["body_sm"]), Paragraph(str(cnt), styles["body_sm"])])

    cat_tbl = Table(cat_rows, colWidths=[None, 22*mm])
    cat_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR",  (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
        ("GRID",       (0, 0), (-1, -1), 0.4, DIVIDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
    ]))
    elems.append(cat_tbl)

    evidence = _report_metadata_value(d, "evidence_strength_breakdown")
    elems.append(Spacer(1, 5*mm))
    elems += sub_header("Evidence Strength", styles)
    elems.append(Paragraph(
        "Findings are grouped by deterministic proof strength, separating confirmed exploits "
        "from observations and review-needed issues.",
        styles["body_sm"],
    ))
    elems.append(_metric_table([
        ("Confirmed Exploit", evidence.get("confirmed_exploit", 0)),
        ("Confirmed Observation", evidence.get("confirmed_observation", 0)),
        ("Probable", evidence.get("probable", 0)),
        ("Possible", evidence.get("possible", 0)),
        ("Informational", evidence.get("informational", 0)),
    ], styles))

    auth = _report_metadata_value(d, "auth_coverage")
    elems.append(Spacer(1, 5*mm))
    elems += sub_header("Authenticated Coverage", styles)
    elems.append(_metric_table([
        ("Auth State", _clean_enum(auth.get("state", "unauthenticated"))),
        ("Authenticated URLs Scanned", auth.get("authenticated_url_count", 0)),
        ("Unauthenticated URLs Scanned", auth.get("unauthenticated_url_count", 0)),
        ("Protected Targets Verified", auth.get("protected_targets_verified", 0)),
        ("Auth Headers Present", auth.get("auth_headers_present", False)),
        ("Session Cookies Present", auth.get("session_cookies_present", False)),
    ], styles))

    spa = _report_metadata_value(d, "spa_api_coverage")
    elems.append(Spacer(1, 5*mm))
    elems += sub_header("SPA / API Coverage", styles)
    elems.append(_metric_table([
        ("SPA Detected", spa.get("spa_detected", False)),
        ("JS Assets Inspected", spa.get("js_assets_inspected", 0)),
        ("Routes Extracted", spa.get("routes_extracted", 0)),
        ("API Endpoints Extracted", spa.get("api_endpoints_extracted", 0)),
        ("Parameters Extracted", spa.get("parameters_extracted", 0)),
        ("Browser Requests Observed", spa.get("browser_requests_observed", 0)),
        ("Dead SPA Fallback Routes Suppressed", spa.get("dead_spa_fallback_routes_suppressed", 0)),
    ], styles))

    limitations = d.get("scanner_limitations") or [
        "OWASP A06, A08, and A09 are disclosed as outside active automated detector scope.",
        "SPA/API coverage depends on crawl visibility and whether browser-based discovery was enabled.",
        "Authenticated coverage is verified only when the scanner proves access to a protected target.",
    ]
    elems.append(Spacer(1, 5*mm))
    elems += sub_header("Scanner Limitations", styles)
    for limitation in limitations:
        elems.append(Paragraph(f"- {_para_escape(limitation)}", styles["body_sm"]))
    return elems


def build_technology_detected(data: dict, styles: dict) -> list:
    d = data.get("data", {})
    technologies = d.get("technology_stack", [])
    elems = section_header("Technology Detected", styles, "3")
    elems.append(Paragraph(
        "The scanner identified the following technologies and checked each detected component for known CVEs.",
        styles["body"],
    ))
    elems.append(Spacer(1, 3*mm))

    if not technologies:
        elems.append(Paragraph("No technologies were detected for this target.", styles["body_sm"]))
        return elems

    rows = [[
        Paragraph("Component", styles["th"]),
        Paragraph("Version", styles["th"]),
        Paragraph("Category", styles["th"]),
        Paragraph("Known CVEs", styles["th"]),
    ]]
    for tech in technologies:
        cves = tech.get("cves", []) or []
        rows.append([
            Paragraph(_para_escape(tech.get("name") or "Unknown"), styles["body_sm"]),
            Paragraph(_para_escape(tech.get("version") or "Unknown"), styles["body_sm"]),
            Paragraph(_para_escape(tech.get("category") or "Unknown"), styles["body_sm"]),
            Paragraph(_para_escape(", ".join(cves) if cves else "None found"), styles["body_sm"]),
        ])

    tbl = Table(rows, colWidths=[42*mm, 28*mm, 32*mm, None])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR",  (0, 0), (-1, 0), WHITE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
        ("GRID",       (0, 0), (-1, -1), 0.4, DIVIDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING",   (0, 0), (-1, -1), 8),
        ("VALIGN",      (0, 0), (-1, -1), "TOP"),
    ]))
    elems.append(tbl)
    return elems


def build_vulnerability_summary(data: dict, styles: dict) -> list:
    d = data.get("data", {})
    vulns = d.get("vulnerabilities", [])
    elems = section_header("Vulnerability Summary", styles, "4")
    elems.append(Paragraph(
        "The table below lists findings ordered by CVSS score, with deterministic evidence "
        "strength and review status shown separately.",
        styles["body"],
    ))
    elems.append(Spacer(1, 3*mm))

    sorted_vulns = sorted(vulns, key=lambda v: v.get("cvss_score", 0), reverse=True)

    header = [
        Paragraph("#", styles["th_center"]),
        Paragraph("Vulnerability", styles["th"]),
        Paragraph("Category", styles["th"]),
        Paragraph("Severity", styles["th"]),
        Paragraph("Evidence", styles["th"]),
        Paragraph("CVSS", styles["th_center"]),
        Paragraph("Review", styles["th"]),
    ]
    rows = [header]
    for i, v in enumerate(sorted_vulns, 1):
        sev   = v.get("severity", "Low")
        sev_display = _clean_enum(sev)
        fg = SEV_FG.get(sev_display, SEV_FG.get(sev, LABEL_TEXT))
        ev = v.get("evidence") or {}
        evidence_strength = v.get("evidence_strength") or ev.get("evidence_strength") or "possible"
        rows.append([
            Paragraph(str(i), styles["body_sm"]),
            Paragraph(_para_escape(v.get("vuln_type", "Unknown")), styles["body_sm"]),
            Paragraph(_para_escape(_clean_category(v.get("category", ""))), styles["body_sm"]),
            Paragraph(f'<font color="#{fg.hexval()[2:]}"><b>{sev_display}</b></font>', styles["body_sm"]),
            Paragraph(_para_escape(_clean_enum(evidence_strength)), styles["body_sm"]),
            Paragraph(f'<b>{v.get("cvss_score", 0):.1f}</b>', styles["body_sm"]),
            Paragraph(_para_escape(_clean_status(v.get("review_status") or "N/A")), styles["body_sm"]),
        ])

    tbl = Table(rows, colWidths=[8*mm, 44*mm, 39*mm, 19*mm, 27*mm, 14*mm, 19*mm])
    style_cmds = [
        ("BACKGROUND", (0, 0), (-1, 0), DARK_BG),
        ("TEXTCOLOR",  (0, 0), (-1, 0), WHITE),
        ("GRID",       (0, 0), (-1, -1), 0.4, DIVIDER),
        ("TOPPADDING",    (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING",   (0, 0), (-1, -1), 5),
        ("VALIGN",     (0, 0), (-1, -1), "MIDDLE"),
    ]
    # Row shading by severity
    for i, v in enumerate(sorted_vulns, 1):
        bg = SEV_BG.get(_clean_enum(v.get("severity", "Low")), WHITE)
        style_cmds.append(("BACKGROUND", (0, i), (-1, i), bg))

    tbl.setStyle(TableStyle(style_cmds))
    elems.append(tbl)
    return elems


def build_detailed_findings(data: dict, styles: dict) -> list:
    d = data.get("data", {})
    vulns = d.get("vulnerabilities", [])
    elems = section_header("Detailed Findings", styles, "5")
    elems.append(Paragraph(
        "Each finding is documented with technical evidence, AI-assisted analysis, "
        "business impact, and exploitability context.",
        styles["body"],
    ))

    sorted_vulns = sorted(vulns, key=lambda v: v.get("cvss_score", 0), reverse=True)

    for idx, v in enumerate(sorted_vulns, 1):
        sev_raw  = v.get("severity", "Low")
        sev      = _clean_enum(sev_raw)
        sev_color = SEV_COLOR.get(sev, MID_GRAY)
        cvss     = v.get("cvss_score", 0)
        loc      = v.get("location", {})
        ev       = v.get("evidence", {})
        ai       = v.get("ai_analysis", {})
        evidence_strength = v.get("evidence_strength") or ev.get("evidence_strength") or "possible"
        auth_context = v.get("auth_context") or ev.get("auth_context") or "unknown"

        block = []

        # ── Finding header bar ──
        block.append(Spacer(1, 4*mm))
        title_tbl = Table(
            [[
                Paragraph(f'<font color="white"><b>Finding #{idx}</b></font>', styles["body_sm"]),
                Paragraph(f'<font color="white"><b>{_para_escape(v.get("vuln_type", "Unknown"))}</b></font>', styles["h3"]),
                Paragraph(f'<font color="white"><b>CVSS {cvss:.1f}</b></font>', styles["body_sm"]),
            ]],
            colWidths=[22*mm, None, 20*mm],
        )
        title_tbl.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), sev_color),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ("LEFTPADDING", (0, 0), (-1, -1), 8),
            ("RIGHTPADDING", (-1, 0), (-1, -1), 8),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        block.append(title_tbl)

        # ── Details grid ──
        def detail_row(label: str, val: str):
            return [
                Paragraph(f"<b>{label}</b>", styles["label"]),
                Paragraph(_para_escape(val) if val else "N/A", styles["body_sm"]),
            ]

        details = [
            detail_row("Category",   _clean_category(v.get("category", ""))),
            detail_row("Severity",   sev),
            detail_row("Evidence Strength", _clean_enum(evidence_strength)),
            detail_row("Auth Context", _clean_enum(auth_context)),
            detail_row("CVSS Vector", v.get("cvss_vector", "N/A")),
            detail_row("URL",         loc.get("url", "N/A")),
            detail_row(
                "Parameters" if len(loc.get("parameters") or []) > 1 else "Parameter",
                ", ".join(loc.get("parameters") or []) or loc.get("parameter") or "N/A",
            ),
            detail_row("Parameter Location", _clean_enum(loc.get("parameter_location") or "N/A")),
            detail_row("HTTP Method", loc.get("http_method", "N/A")),
            detail_row("Detection Method", ev.get("detection_method") or "N/A"),
            detail_row("Detector Verified", _display_value(ev.get("verified"))),
            detail_row("Review Status", _clean_status(v.get("review_status") or "N/A")),
            detail_row("Detected At",  _fmt_dt(v.get("detected_at"))),
        ]
        det_tbl = Table(details, colWidths=[35*mm, None])
        det_tbl.setStyle(TableStyle([
            ("ROWBACKGROUNDS", (0, 0), (-1, -1), [LIGHT_BG, WHITE]),
            ("GRID",       (0, 0), (-1, -1), 0.3, DIVIDER),
            ("TOPPADDING",    (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
            ("LEFTPADDING",   (0, 0), (-1, -1), 6),
        ]))
        block.append(det_tbl)
        block.append(Spacer(1, 3*mm))

        # ── Business Impact ──
        block.append(Spacer(1, 3*mm))
        block.append(Paragraph("BUSINESS IMPACT", styles["label"]))
        block.append(Spacer(1, 1*mm))
        block.append(Paragraph(_para_escape(ai.get("business_impact", "N/A")), styles["body_sm"]))
        block.append(Spacer(1, 3*mm))

        # ── Exploitability ──
        exploit = _clean_enum(ai.get("exploitability", "N/A"))
        exploit_note = ai.get("exploitability_reasoning", "")
        block.append(Paragraph("EXPLOITABILITY", styles["label"]))
        block.append(Spacer(1, 1*mm))
        block.append(Paragraph(f"<b>{_para_escape(exploit)}</b> - {_para_escape(exploit_note)}", styles["body_sm"]))
        block.append(Spacer(1, 3*mm))

        # ── Evidence ──
        payload = ev.get("payload")
        if payload:
            block.append(Spacer(1, 2*mm))
            block.append(Paragraph("PAYLOAD USED", styles["label"]))
            block.append(Spacer(1, 1.5*mm))
            block.append(full_code_block(payload, styles))
            block.append(Spacer(1, 3*mm))

        req = ev.get("request_snippet")
        if req:
            block.append(Paragraph("REQUEST SNIPPET", styles["label"]))
            block.append(Spacer(1, 1.5*mm))
            block.append(full_code_block(req.strip(), styles))
            block.append(Spacer(1, 3*mm))

        resp = ev.get("response_snippet")
        if resp:
            evidence_text, excerpt_text = _split_response_evidence(resp)
            if evidence_text:
                block.append(Paragraph("VERIFICATION EVIDENCE", styles["label"]))
                block.append(Spacer(1, 1.5*mm))
                block.append(Paragraph(_para_escape(evidence_text), styles["body_sm"]))
                block.append(Spacer(1, 3*mm))
            if excerpt_text:
                block.append(Paragraph("RESPONSE EXCERPT" if evidence_text else "RESPONSE SNIPPET", styles["label"]))
                block.append(Spacer(1, 1.5*mm))
                block.append(full_code_block(excerpt_text, styles))
                block.append(Spacer(1, 3*mm))

        # ── False positive info ──
        fp_prob = ai.get("false_positive_probability", 0)
        fp_pct  = int(fp_prob * 100)
        block.append(Spacer(1, 2*mm))
        block.append(Paragraph(
            f"<b>False Positive Probability:</b> {fp_pct}%  |  "
            f"<b>AI Analysis Status:</b> {_clean_status(ai.get('ai_analysis_status', 'N/A'))}",
            styles["caption"],
        ))

        elems.append(KeepTogether(block[:6]))  # keep header + details together
        elems.extend(block[6:])
        elems.append(HRFlowable(width="100%", thickness=0.5, color=DIVIDER,
                                spaceBefore=4, spaceAfter=2))

    return elems


def build_remediation_roadmap(data: dict, styles: dict) -> list:
    d = data.get("data", {})
    vulns = d.get("vulnerabilities", [])
    elems = section_header("Remediation Roadmap", styles, "6")
    elems.append(Paragraph(
        "The following roadmap prioritises remediation actions by severity and exploitability. "
        "Immediate attention should be given to Critical findings before addressing lower-severity items.",
        styles["body"],
    ))
    elems.append(Spacer(1, 3*mm))

    phases = {
        "Immediate (Critical)": [],
        "Short-Term (Medium / Easy)": [],
        "Mid-Term (Medium)": [],
        "Long-Term (Low)": [],
    }
    for v in vulns:
        sev    = _clean_enum(v.get("severity", "Low"))
        exploi = _clean_enum(v.get("ai_analysis", {}).get("exploitability", "Medium"))
        if sev == "Critical":
            phases["Immediate (Critical)"].append(v)
        elif sev in ("High", "Medium") and exploi == "Easy":
            phases["Short-Term (Medium / Easy)"].append(v)
        elif sev == "Medium":
            phases["Mid-Term (Medium)"].append(v)
        else:
            phases["Long-Term (Low)"].append(v)

    for phase, items in phases.items():
        if not items:
            continue
        elems += sub_header(phase, styles)
        rows = [[
            Paragraph("Vulnerability", styles["th"]),
            Paragraph("Action", styles["th"]),
        ]]
        for v in items:
            rem = v.get("ai_analysis", {}).get("remediation", "See full finding for details.")
            rows.append([
                Paragraph(_para_escape(v.get("vuln_type", "Unknown")), styles["body_sm"]),
                Paragraph(_para_escape(rem), styles["body_sm"]),
            ])
        tbl = Table(rows, colWidths=[55*mm, None])
        tbl.setStyle(TableStyle([
            ("BACKGROUND",  (0, 0), (-1, 0), DARK_BG),
            ("TEXTCOLOR",   (0, 0), (-1, 0), WHITE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, LIGHT_BG]),
            ("GRID",        (0, 0), (-1, -1), 0.4, DIVIDER),
            ("TOPPADDING",     (0, 0), (-1, -1), 5),
            ("BOTTOMPADDING",  (0, 0), (-1, -1), 5),
            ("LEFTPADDING",    (0, 0), (-1, -1), 6),
            ("VALIGN",      (0, 0), (-1, -1), "TOP"),
        ]))
        elems.append(tbl)
        elems.append(Spacer(1, 3*mm))

    return elems


# ─────────────────────────── Public API ─────────────────────────────────── #

def build_scan_pdf(scan_data: dict | None = None,
                   json_path: str | None = None) -> bytes:
    """
    Generate a professional pentest report PDF.

    Parameters
    ----------
    scan_data : dict, optional
        Already-parsed scan JSON dict.
    json_path : str, optional
        Path to a scan JSON file to load.

    Returns
    -------
    bytes
        Raw PDF bytes.
    """
    if scan_data is None and json_path:
        with open(json_path, "r", encoding="utf-8") as f:
            scan_data = json.load(f)
    if scan_data is None:
        raise ValueError("Provide either scan_data or json_path.")

    buf    = BytesIO()
    doc    = make_doc(buf, scan_data)
    styles = build_styles()

    story: list = []

    # ── Cover page (drawn via PageTemplate onPage callback) ──
    story.append(NextPageTemplate("Normal"))
    story.append(PageBreak())

    # ── Body sections ──
    story += build_toc(scan_data, styles)
    story.append(PageBreak())

    story += build_executive_summary(scan_data, styles)
    story.append(PageBreak())

    story += build_statistics(scan_data, styles)
    story.append(PageBreak())

    story += build_technology_detected(scan_data, styles)
    story.append(PageBreak())

    story += build_vulnerability_summary(scan_data, styles)
    story.append(PageBreak())

    story += build_detailed_findings(scan_data, styles)
    story.append(PageBreak())

    story += build_remediation_roadmap(scan_data, styles)

    doc.build(story)

    buf.seek(0)
    return buf.read()
