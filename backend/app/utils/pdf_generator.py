from io import BytesIO

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def build_scan_pdf(title: str, sections: list[tuple[str, str]]) -> bytes:
    buffer = BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)

    width, height = letter
    y = height - 50

    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(50, y, title)
    y -= 30

    for section_title, content in sections:
        if y < 120:
            pdf.showPage()
            y = height - 50
        pdf.setFont("Helvetica-Bold", 12)
        pdf.drawString(50, y, section_title)
        y -= 18
        pdf.setFont("Helvetica", 10)
        for line in content.splitlines() or [""]:
            if y < 80:
                pdf.showPage()
                y = height - 50
                pdf.setFont("Helvetica", 10)
            pdf.drawString(55, y, line[:140])
            y -= 14
        y -= 8

    pdf.save()
    buffer.seek(0)
    return buffer.read()
