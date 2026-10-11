"""Rapport PDF professionnel : bandeau, synthèse par sévérité, constats colorés, pagination."""
from io import BytesIO
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import KeepTogether, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

SEV = {"critical": "#c62839", "high": "#e4572e", "medium": "#d98a1c", "low": "#2a9d8f", "info": "#4a7fb5"}
INK, TEAL, LINE = colors.HexColor("#0b1b2d"), colors.HexColor("#087f8c"), colors.HexColor("#d5dde5")


def _frame(canvas, doc):
    w, h = A4
    canvas.saveState()
    canvas.setFillColor(INK)
    canvas.rect(0, h - 22 * mm, w, 22 * mm, stroke=0, fill=1)
    canvas.setFillColor(colors.white)
    canvas.setFont("Helvetica-Bold", 15)
    canvas.drawString(18 * mm, h - 13 * mm, "AgAtA-SpiDeR")
    canvas.setFillColor(colors.HexColor("#5cecff"))
    canvas.setFont("Helvetica", 8)
    canvas.drawString(18 * mm, h - 18 * mm, "RAPPORT D'AUDIT DE SÉCURITÉ")
    canvas.setFillColor(colors.grey)
    canvas.drawString(18 * mm, 10 * mm, "Confidentiel — usage autorisé uniquement")
    canvas.drawRightString(w - 18 * mm, 10 * mm, f"Page {doc.page}")
    canvas.restoreState()


def create_pdf(audit: dict) -> bytes:
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=30 * mm,
                            bottomMargin=18 * mm, title="AgAtA-SpiDeR — Rapport d'audit", author="AgAtA-SpiDeR")
    ss = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=ss["BodyText"], fontSize=9, leading=12.5)
    small = ParagraphStyle("small", parent=body, fontSize=8, textColor=colors.HexColor("#5b6b7c"))
    bold = ParagraphStyle("bold", parent=body, fontName="Helvetica-Bold", fontSize=10)
    white = ParagraphStyle("white", parent=small, textColor=colors.white, alignment=1, fontName="Helvetica-Bold")
    big = ParagraphStyle("big", parent=white, fontSize=16, leading=20)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=TEAL, spaceBefore=12, spaceAfter=6)
    title = ParagraphStyle("title", parent=ss["Title"], textColor=INK, alignment=0, fontSize=20, spaceAfter=10)

    def p(v, st):
        return Paragraph(escape(str(v if v is not None else "—")), st)

    findings = audit.get("findings", [])
    meta = [("ID audit", audit.get("audit_id")), ("Mode", audit.get("mode")),
            ("Cible", audit.get("target_label") or audit.get("target")), ("Engagement", audit.get("engagement_id")),
            ("Créé (UTC)", audit.get("created_at")), ("Statut", audit.get("status")),
            ("SHA-256 des constats", audit.get("findings_hash_sha256"))]
    mt = Table([[p(k, small), p(v, body)] for k, v in meta], colWidths=[38 * mm, 130 * mm])
    mt.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -1), .3, LINE),
                            ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    story = [Paragraph("Rapport d'audit de sécurité", title), mt, Spacer(1, 8)]

    if any(f.get("simulated") for f in findings):
        bn = Table([[p("DONNÉES SIMULÉES — aucune requête n'a été envoyée à une cible.", body)]], colWidths=[168 * mm])
        bn.setStyle(TableStyle([("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#fff3d6")),
                                ("BOX", (0, 0), (-1, -1), .6, colors.HexColor("#d98a1c")), ("PADDING", (0, 0), (-1, -1), 6)]))
        story += [bn, Spacer(1, 8)]

    story.append(Paragraph("Synthèse par sévérité", h2))
    order = list(SEV)
    st = Table([[p(k.upper(), white) for k in order],
                [p(sum(1 for f in findings if f.get("severity") == k), big) for k in order]], colWidths=[33.6 * mm] * 5)
    st.setStyle(TableStyle([("BACKGROUND", (i, 0), (i, 1), colors.HexColor(SEV[k])) for i, k in enumerate(order)]
                           + [("ALIGN", (0, 0), (-1, -1), "CENTER"), ("PADDING", (0, 0), (-1, -1), 5),
                              ("LINEAFTER", (0, 0), (-2, -1), 1, colors.white)]))
    story.append(st)

    ai = audit.get("ai") or {}
    if ai.get("enabled"):
        story += [Paragraph("Synthèse IA (avis consultatif, non probant)", h2),
                  Paragraph(escape(ai.get("summary", "")).replace("\n", "<br/>"), body)]
        story += [Paragraph("• " + escape(str(r)), body) for r in ai.get("recommendations", [])]

    story.append(Paragraph("Constats", h2))
    if not findings:
        story.append(p("Aucun constat n'est disponible pour cet audit.", body))
    for i, f in enumerate(findings, 1):
        sev = str(f.get("severity", "info"))
        cell = [p(f"{i}. {f.get('title', 'Constat')}", bold), p(f.get("description", ""), body),
                p("Preuve : " + str(f.get("evidence", "")), small)]
        if f.get("recommendation"):
            cell.append(p("Recommandation : " + str(f["recommendation"]), body))
        t = Table([[p(sev.upper(), white), cell]], colWidths=[22 * mm, 146 * mm])
        t.setStyle(TableStyle([("BACKGROUND", (0, 0), (0, 0), colors.HexColor(SEV.get(sev, SEV["info"]))),
                               ("VALIGN", (0, 0), (-1, -1), "TOP"), ("BOX", (0, 0), (-1, -1), .5, LINE),
                               ("PADDING", (0, 0), (-1, -1), 6)]))
        story += [KeepTogether(t), Spacer(1, 6)]

    story += [Paragraph("Limites et interprétation", h2),
              p("Les constats s'interprètent dans le périmètre autorisé. Un contrôle TCP ne identifie pas de vulnérabilité. "
                "Les données de démonstration sont simulées. Les recommandations générées par IA ne constituent pas des preuves.", body)]
    doc.build(story, onFirstPage=_frame, onLaterPages=_frame)
    return buf.getvalue()
