from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.pdfgen import canvas
from reportlab.lib import colors


def create_business_card(c, x, y, name, street, city, tel, email, image_path):
    """
    Erstellt eine einzelne Visitenkarte an einer bestimmten Position (x, y) auf dem Canvas.
    Die Abmessungen sind 9 cm breit und 5 cm hoch.
    """
    card_width = 9 * cm
    card_height = 5 * cm

    # Rahmen (optional, zum besseren Verständnis)
    c.setStrokeColor(colors.lightgrey)
    c.rect(x, y, card_width, card_height)

    # Name
    c.setFont("Helvetica-Bold", 14)
    c.drawString(x + 0.5 * cm, y + card_height - 0.7 * cm, name)

    # Adresse und Kontaktdaten
    c.setFont("Helvetica", 10)
    text_y = y + card_height - 1.8 * cm
    line_spacing = 0.4 * cm

    c.drawString(x + 0.5 * cm, text_y, street)
    text_y -= line_spacing
    c.drawString(x + 0.5 * cm, text_y, city)
    text_y -= line_spacing
    c.drawString(x + 0.5 * cm, text_y, f"Tel: {tel}")
    text_y -= line_spacing
    c.drawString(x + 0.5 * cm, text_y, email)

    # Bild
    try:
        # Passen Sie die Position und Größe des Bildes an
        img_width = 3 * cm
        img_height = 3 * cm
        img_x = x + card_width - img_width - 0.5 * cm
        img_y = y + 0.5 * cm
        c.drawImage(
            image_path,
            img_x,
            img_y,
            width=img_width,
            height=img_height,
            preserveAspectRatio=True,
            anchor="n",
        )
    except Exception as e:
        print(f"Fehler beim Laden des Bildes: {e}")
        c.drawString(img_x, img_y, "Bild nicht gefunden")


def create_a4_sheet(output_filename, user_data):
    """
    Erstellt ein PDF-Dokument mit 8 Visitenkarten (2x4) auf einem DIN A4-Blatt.
    """
    c = canvas.Canvas(output_filename, pagesize=A4)

    # Visitenkarten-Größe in Punkten (1 cm = 28.3464567 Punkte)
    card_width = 9 * cm
    card_height = 5 * cm

    # Anordnung der Karten (2 Spalten, 4 Reihen)
    num_cols = 2
    num_rows = 4

    # Abstände berechnen, um die Karten zu zentrieren
    total_cards_width = num_cols * card_width
    total_cards_height = num_rows * card_height
    x_margin = (A4[0] - total_cards_width) / 2
    y_margin = (A4[1] - total_cards_height) / 2

    # Schleife zum Erstellen der 8 Karten
    for row in range(num_rows):
        for col in range(num_cols):
            x = x_margin + col * card_width
            y = y_margin + (num_rows - 1 - row) * card_height

            # Übergabe der Benutzerdaten
            create_business_card(
                c,
                x,
                y,
                user_data["name"],
                user_data["street"],
                user_data["city"],
                user_data["tel"],
                user_data["email"],
                user_data["image_path"],
            )

    c.save()
    print(f"Visitenkarten wurden als '{output_filename}' erstellt. 🎉")


if __name__ == "__main__":
    # 📝 HIER IHRE DATEN EINGEBEN UND ANPASSEN
    my_data = {
        "name": "Siegfried Wunderlich",
        "street": "Breslauerstr 14",
        "city": "97072 Würzburg",
        "tel": "0931/26019960",
        "email": "sanderware1@yahoo.de",
        "image_path": "Visitenkarte.jpg",  # 🖼️ HIER den Dateinamen Ihres Bildes angeben
    }

    create_a4_sheet("Visitenkarten_print.pdf", my_data)
