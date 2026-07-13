import os
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from config import REPORT_DIR


def generate_pdf_report(scan):
    os.makedirs(REPORT_DIR, exist_ok=True)

    filename = f"scan_report_{scan['id']}.pdf"
    filepath = os.path.join(REPORT_DIR, filename)

    pdf = canvas.Canvas(filepath, pagesize=A4)
    width, height = A4

    y = height - 50

    pdf.setFont("Helvetica-Bold", 18)
    pdf.drawString(50, y, "Phishing Website Detection Report")

    y -= 40
    pdf.setFont("Helvetica", 11)
    pdf.drawString(50, y, f"Report ID: {scan['id']}")

    y -= 20
    pdf.drawString(50, y, f"Scanned At: {scan['scanned_at']}")

    y -= 30
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "URL Information")

    y -= 25
    pdf.setFont("Helvetica", 10)
    pdf.drawString(50, y, f"URL: {scan['url'][:95]}")

    y -= 20
    pdf.drawString(50, y, f"Domain: {scan['domain']}")

    y -= 30
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "Detection Result")

    y -= 25
    pdf.setFont("Helvetica", 11)
    pdf.drawString(50, y, f"Final Prediction: {scan['prediction']}")

    y -= 20
    pdf.drawString(50, y, f"ML Prediction: {scan['ml_prediction']}")

    y -= 20
    pdf.drawString(50, y, f"Risk Score: {scan['risk_score']}%")

    y -= 20
    pdf.drawString(50, y, f"ML Phishing Probability: {scan['ml_probability']}")

    y -= 20
    pdf.drawString(50, y, f"Blacklisted: {'Yes' if scan['is_blacklisted'] else 'No'}")

    y -= 20
    pdf.drawString(50, y, f"Domain Age Days: {scan['domain_age_days']}")

    y -= 35
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "Explanation")

    y -= 25
    pdf.setFont("Helvetica", 10)

    for reason in scan["reasons"]:
        if y < 80:
            pdf.showPage()
            y = height - 50
            pdf.setFont("Helvetica", 10)

        pdf.drawString(60, y, f"- {reason[:100]}")
        y -= 18

    y -= 20
    pdf.setFont("Helvetica-Bold", 13)
    pdf.drawString(50, y, "Important Note")

    y -= 20
    pdf.setFont("Helvetica", 10)
    pdf.drawString(
        50,
        y,
        "This system provides automated risk analysis. Final decisions should include manual verification."
    )

    pdf.save()

    return filepath