"""PDF reports from the exact stored scan, without extra outbound requests."""
import io
import json
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, KeepTogether


def build_report(scan: dict) -> io.BytesIO:
    output = io.BytesIO()
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Evidence", parent=styles["BodyText"], fontSize=9, leading=12, spaceAfter=4, wordWrap="CJK"))
    styles["Title"].textColor = colors.HexColor("#b51e2d")
    styles["Heading2"].textColor = colors.HexColor("#b51e2d")
    width = A4[0] - 84
    doc = SimpleDocTemplate(output, pagesize=A4, rightMargin=42, leftMargin=42, topMargin=48, bottomMargin=48, title="Phish-X AI Security Report", author="Phish-X AI")
    story = []
    def text(value, style="Evidence"):
        # Helvetica supports Latin text but not every punctuation/website glyph.
        # Normalize typographic dashes and retain other unsupported characters as
        # explicit Unicode escapes rather than invisible squares or lost evidence.
        printable = unicodedata.normalize('NFKC', str(value))
        printable = printable.translate(str.maketrans({'\u2010':'-', '\u2011':'-', '\u2012':'-', '\u2013':'-', '\u2014':'-', '\u2212':'-', '\u2018':"'", '\u2019':"'", '\u201c':'"', '\u201d':'"'}))
        printable = printable.encode('cp1252', errors='backslashreplace').decode('cp1252')
        return Paragraph(escape(printable).replace("\n", "<br/>"), styles[style])
    def section(label):
        story.append(Paragraph(escape(label), styles["Heading2"]))
    def table(rows):
        # Bound individual table rows so attacker-controlled long titles/domain lists cannot
        # exceed one page. The complete ledger stays available in the saved scan.
        def report_value(value):
            value = str(value)
            return value if len(value) <= 1800 else value[:1800] + " [Report excerpt; see the stored scan for complete evidence.]"
        cells = [[text(key), text(report_value(value))] for key, value in rows]
        element = Table(cells, colWidths=[140, width - 140], hAlign="LEFT")
        element.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#f3f3f3")), ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#dddddd")), ("VALIGN", (0, 0), (-1, -1), "TOP"), ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8), ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6)]))
        story.append(element)
    logo = Path(__file__).parent / "static/images/logo.png"
    if logo.exists():
        from PIL import Image as PILImage
        with PILImage.open(logo) as im:
            ratio = im.height / im.width
        header = Table([[Image(str(logo), width=130, height=130 * ratio)]], colWidths=[width], hAlign="LEFT")
        header.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#181818")), ("TOPPADDING", (0,0), (-1,-1), 8), ("BOTTOMPADDING", (0,0), (-1,-1), 8)]))
        story.append(header)
        story.append(Spacer(1, 12))
    story.append(text("Phish-X AI Security Report", "Title"))
    story.append(text("AI-powered phishing and website threat analysis. AI availability is reported below."))
    section("Scan identity and assessment")
    table([("Submitted URL", scan["url"]), ("Scan ID", scan["scan_id"]), ("Scan time (UTC)", scan["timestamp"]),
           ("Assessment", scan["assessment"]), ("Observed risk score", f"{scan['risk_score']}/100 - {scan['severity']}"), ("Analysis state", scan["state"]), ("Recommended action", scan["recommendation"])])
    story.append(Spacer(1, 8))
    story.append(text(scan["score_note"]))
    section("Major evidence and score contributions")
    significant = [finding for finding in scan["evidence"] if finding["points"] > 0]
    if not significant:
        story.append(text("No scoring indicators were observed in the available evidence. Missing data is not proof of safety."))
    for finding in significant:
        story.append(text(f"{finding['label']} (+{finding['points']} points; {finding['id']})", "Heading3"))
        story.append(text("Observed: " + json.dumps(finding["detail"], ensure_ascii=True)[:3500]))
        story.append(text("Source: " + finding["source"] + " | Type: " + finding["kind"]))
    section("Website crawl and attack surface")
    features, surface = scan["features"], scan["attack_surface"]
    http, content = features.get("http", {}), features.get("content", {})
    table([("HTTP fetch", http.get("status")), ("Status code", http.get("status_code", "Unavailable")), ("Final URL", http.get("final_url") or "Unavailable"),
           ("Page title", content.get("title") or "Unavailable"), ("Forms", surface.get("forms") if surface.get("forms") is not None else "Unavailable"),
           ("Password fields", surface.get("password_fields") if surface.get("password_fields") is not None else "Unavailable"),
           ("Payment fields", surface.get("payment_fields") if surface.get("payment_fields") is not None else "Unavailable"),
           ("Scripts / iframes", f"{surface.get('scripts')} / {surface.get('iframes')}"), ("Redirects observed", surface["redirects"]),
           ("External domains", ", ".join(surface.get("external_domains") or []) or "Unavailable or none observed"), ("TLS", json.dumps(features.get("certificate", {}), ensure_ascii=True)),
           ("DNS addresses", ", ".join(features.get("dns", {}).get("addresses", [])) or "Unavailable"), ("Domain registration", json.dumps(features.get("domain_age", {}), ensure_ascii=True))])
    for hop in features.get("redirection", {}).get("chain", []):
        story.append(text(f"Redirect HTTP {hop['status_code']}: {hop['from']} -> {hop['to']}"))
    section("Threat intelligence")
    vt, gsb = features.get("virus_total", {}), features.get("google_safe_browsing", {})
    rows = [("VirusTotal status", vt.get("status", "Unavailable"))]
    if "total" in vt:
        rows += [(name.capitalize(), vt.get(name)) for name in ("malicious", "suspicious", "harmless", "undetected", "total")]
        date = vt.get("analysis_date")
        try:
            date = datetime.fromtimestamp(date, timezone.utc).isoformat() if type(date) in {int, float} else "Unavailable"
        except (ValueError, OverflowError, OSError):
            date = "Unavailable"
        rows += [("Analysis time (UTC)", date)]
    else:
        rows += [("VirusTotal detail", vt.get("error") or vt.get("reason") or "Analysis pending; no completed counts available.")]
    rows += [("Safe Browsing status", gsb.get("status")), ("Safe Browsing matches", json.dumps(gsb.get("matches", []), ensure_ascii=True) if gsb.get("status") == "completed" else "Unavailable")]
    table(rows)
    for vendor in vt.get("vendors", []):
        story.append(text(f"{vendor['vendor']}: {vendor['category']} - {vendor['result']}"))
    section("Phishing DNA and security headers")
    table([(item["label"], f"{item['points']} / {item['cap']} evidence points" if item["available"] else "Unavailable") for item in scan["phishing_dna"]])
    for name, value in features.get("security_headers", {}).items():
        story.append(text(f"{name}: {value or ('Not present' if http.get('status_code') else 'Unavailable')}"))
    section("AI evidence reasoning")
    ai = scan["ai"]
    if ai["status"] == "completed":
        table([("AI assessment", ai["assessment"]), ("Provider / model", f"{ai['provider']} / {ai['model']}"),
               ("AI confidence", f"{ai['confidence'] * 100:.0f}% (self-reported, not calibrated)"), ("AI recommended action", ai["recommended_action"])])
        for reason in ai["key_reasons"]:
            story.append(text(reason["interpretation"]))
            story.append(text("Supporting evidence: " + ", ".join(reason["evidence_ids"])))
        for limitation in ai["limitations"]:
            story.append(text("AI limitation: " + limitation))
    else:
        story.append(text(f"AI {ai['status']}: {ai.get('reason', 'No AI result available.')}"))
    section("Evidence timeline and coverage limits")
    for step in scan["timeline"]:
        story.append(text(f"{step['timestamp']} | {step['stage']} | {step['status']} | {step['detail']}"))
    for source in scan["unavailable"]:
        story.append(text(f"Unavailable: {source['source']} ({source['status']}) - {source['reason']}"))
    story.append(text(surface["note"]))
    def page(canvas, document):
        canvas.saveState()
        canvas.setStrokeColor(colors.HexColor("#b51e2d"))
        canvas.line(42, 35, A4[0] - 42, 35)
        canvas.setFont("Helvetica", 8)
        canvas.drawString(42, 23, "Phish-X AI | Report from stored evidence; no second scan")
        canvas.drawRightString(A4[0] - 42, 23, f"Page {document.page}")
        canvas.restoreState()
    doc.build(story, onFirstPage=page, onLaterPages=page)
    output.seek(0)
    return output
