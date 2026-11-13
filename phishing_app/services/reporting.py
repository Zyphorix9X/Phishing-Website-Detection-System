from __future__ import annotations

from html import escape
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from risk_summary import summarize_risk
from time_utils import format_sri_lanka_time


NAVY = colors.HexColor("#0b1422")
TEAL = colors.HexColor("#20d6c2")
MUTED = colors.HexColor("#5c6a7c")


def generate_pdf_report(scan, user=None) -> bytes:
    data = scan.result_data or {}
    research = data.get('model_deployment_status') != 'validated' or bool(data.get('model_warning'))
    risk = summarize_risk(data)
    stream = BytesIO()
    document = SimpleDocTemplate(
        stream, pagesize=A4, rightMargin=18 * mm, leftMargin=18 * mm,
        topMargin=24 * mm, bottomMargin=20 * mm, title=f"Sentinel URL analysis {scan.id}",
        author="Sentinel Security Intelligence",
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallMuted", parent=styles["BodyText"], textColor=MUTED, fontSize=8, leading=11))
    styles.add(ParagraphStyle(name="Section", parent=styles["Heading2"], textColor=NAVY, spaceBefore=12, spaceAfter=6))
    styles.add(ParagraphStyle(name="LongURL", parent=styles["BodyText"], wordWrap="CJK", fontSize=8, leading=11))
    story = [
        Paragraph("SENTINEL <font color='#20d6c2'>/</font> SECURITY INTELLIGENCE", styles["Heading2"]),
        Paragraph("URL analysis report", styles["Title"]),
        Paragraph("Automated URL analysis from locally available model and threat-intelligence evidence.", styles["SmallMuted"]),
        Spacer(1, 8 * mm),
    ]
    url = escape(str(scan.submitted_url or ""))
    verdict = escape(str(scan.prediction or "UNVERIFIED"))
    owner = escape(str(user.full_name if user else "Account owner"))
    scanned_at = escape(format_sri_lanka_time(data.get('scanned_at') or scan.created_at))
    story.append(_section("Overview", styles))
    story.append(_table([
        ["Report ID", f"SNT-{scan.id:06d}"], ["Account", owner], ["Submitted URL", Paragraph(url, styles["LongURL"])],
        ["Verdict", verdict], ["Risk indicator score", risk['risk_percentage_display'] + ' (heuristic index)'],
        ["Model use", 'Excluded from verdict: research model' if research else 'Validated model'], ["Scanned at", scanned_at],
    ]))
    if data.get('decision_explanation'):
        story.append(Paragraph(escape(str(data.get('decision_explanation', ''))), styles['SmallMuted']))
    story.append(Paragraph(escape(risk['risk_percentage_explanation']), styles['SmallMuted']))
    if data.get('prediction', scan.prediction) == 'UNVERIFIED':
        story.append(Paragraph('Verification is incomplete. A low percentage does not establish that the URL is safe.', styles['SmallMuted']))
    story.append(_section("Domain intelligence", styles))
    domain = data.get("whois", {})
    story.append(_table([
        ["Registered domain", escape(str(domain.get("domain") or "Unavailable"))],
        ["Lookup status", escape(str(domain.get("lookup_status", "unavailable")).replace("_", " ").title())],
        ["Domain age", f"{domain['domain_age_days']} days" if domain.get("domain_age_days") is not None else "Unavailable"],
        ["Registrar", escape(str(domain.get("registrar") or "Unavailable"))],
    ]))
    story.append(_section("Threat intelligence", styles))
    intel_rows = [["Provider", "Status", "Evidence"]]
    for item in data.get("threat_intelligence", []):
        evidence = item.get("evidence", {})
        intel_rows.append([
            escape(str(item.get("provider", "Unknown"))),
            escape(str(item.get("status", "unavailable")).replace("_", " ").title()),
            Paragraph(escape(", ".join(f"{k}: {v}" for k, v in evidence.items()) or "No evidence"), styles["SmallMuted"]),
        ])
    story.append(_table(intel_rows, header=True))
    story.append(_section("Security indicators", styles))
    if 'url_indicator_score' in data:
        story.append(Paragraph(f"Observed URL indicator points: {data['url_indicator_score']}. These points are not a probability or an overall safety rating.", styles['SmallMuted']))
    if 'url_indicators' not in data:
        story.append(Paragraph('Historical rule notes follow. Run a new scan for the current contextual rules.', styles['SmallMuted']))
    reasons = [f"{item['description']} ({item['points']} points)" for item in data['url_indicators']] if 'url_indicators' in data else data.get('reasons', [])
    if reasons:
        story.extend(Paragraph(f"- {escape(str(reason))}", styles["BodyText"]) for reason in reasons)
    else:
        story.append(Paragraph("No rule-based indicators were recorded.", styles["BodyText"]))
    story.append(_section("Experimental model details" if research else "Model details", styles))
    story.append(Paragraph(f"Raw classifier score: {_probability(scan.ml_probability)}. Raw class vote: {escape(str(data.get('ml_prediction', scan.ml_prediction)))}.", styles['BodyText']))
    if data.get('model_warning'):
        story.append(Paragraph(escape(str(data['model_warning'])), styles['SmallMuted']))
    if research:
        story.append(Paragraph('This output is excluded from the verdict and overall risk rating. It is not a confirmed detection.', styles['SmallMuted']))
    explanation = data.get("model_explanation", {})
    if explanation.get("items"):
        for item in explanation["items"]:
            if explanation.get("method") == "shap_tree_explainer":
                wording = "is attributed to increase" if item.get("direction") == "increases" else "is attributed to decrease"
                description = f"{escape(str(item.get('feature', 'Feature')))} {wording} the model phishing score by {item.get('change', 0)} percentage points (SHAP)."
            else:
                description = f"Removing {escape(str(item.get('feature', 'Feature')))} changes the model phishing score by approximately {item.get('change', 0)} percentage points."
            story.append(Paragraph(description, styles["BodyText"]))
    else:
        story.append(Paragraph("A local model explanation was unavailable for this result. Rule indicators are listed separately above.", styles["BodyText"]))
    story.append(_section("Interpretation and recommended action", styles))
    story.append(Paragraph(_verdict_guidance(scan.prediction), styles["BodyText"]))
    story.append(Spacer(1, 4 * mm))
    story.append(Paragraph(
        "The model score is an uncalibrated classifier output. The heuristic risk index is not a probability. "
        "A LEGITIMATE result means this analysis did not cross the configured phishing thresholds; it is not proof that a website is safe. "
        "Screenshot and live webpage analysis were not performed.",
        styles["SmallMuted"],
    ))
    document.build(story, onFirstPage=_page_chrome, onLaterPages=_page_chrome)
    return stream.getvalue()


def _section(title, styles):
    return Paragraph(escape(title), styles["Section"])


def _table(rows, header=False):
    if not header:
        rows = [[Paragraph(escape(str(row[0])), _small_style()), row[1]] for row in rows]
    widths = [38 * mm, 35 * mm, 91 * mm] if header and len(rows[0]) == 3 else [48 * mm, 116 * mm]
    table = Table(rows, colWidths=widths, repeatRows=1 if header else 0, hAlign="LEFT")
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f4f7fa")),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.35, colors.HexColor("#d6e0e8")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LEFTPADDING", (0, 0), (-1, -1), 7),
        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]))
    if header:
        table.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), colors.white), ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold")]))
    return table


def _small_style():
    return ParagraphStyle("ReportLabel", fontName="Helvetica-Bold", fontSize=8, leading=10, textColor=NAVY)


def _probability(value):
    return f"{float(value):.1%} (not calibrated)" if value is not None else "Unavailable"


def _verdict_guidance(verdict):
    guidance = {
        "PHISHING": "Avoid visiting the URL or entering information. Report the link through your organization’s security process.",
        "SUSPICIOUS": "Do not enter credentials or payment details. Verify the destination through a known, independent channel.",
        "LEGITIMATE": "No phishing threshold was reached by the configured checks. Verify the sender and destination before sharing sensitive information.",
        "UNVERIFIED": "Available evidence could not verify this URL. This is not a finding that the URL is malicious. Confirm the destination through a trusted channel.",
    }
    return guidance.get(verdict, guidance["UNVERIFIED"])


def _page_chrome(canvas, document):
    canvas.saveState()
    width, height = A4
    canvas.setFillColor(NAVY)
    canvas.rect(0, height - 12 * mm, width, 12 * mm, fill=1, stroke=0)
    canvas.setFillColor(TEAL)
    canvas.setFont("Helvetica-Bold", 8)
    canvas.drawString(18 * mm, height - 8 * mm, "SENTINEL / SECURITY INTELLIGENCE")
    canvas.setFillColor(MUTED)
    canvas.setFont("Helvetica", 8)
    canvas.drawString(18 * mm, 11 * mm, "Confidential scan report · For security review")
    canvas.drawRightString(width - 18 * mm, 11 * mm, f"Page {document.page}")
    canvas.restoreState()
