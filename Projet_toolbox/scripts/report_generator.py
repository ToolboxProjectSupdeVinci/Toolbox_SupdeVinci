from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

def generate_report(content, file_path):
    c = canvas.Canvas(file_path, pagesize=A4)
    width, height = A4
    text = c.beginText(40, height - 40)
    text.setFont("Helvetica", 12)
    
    lines_per_page = 60  # Adjust this number based on the font size and page size
    lines = content.split('\n')
    for i, line in enumerate(lines):
        if i % lines_per_page == 0 and i != 0:
            c.drawText(text)
            c.showPage()
            text = c.beginText(40, height - 40)
            text.setFont("Helvetica", 12)
        text.textLine(line)
    
    c.drawText(text)
    c.showPage()
    c.save()
