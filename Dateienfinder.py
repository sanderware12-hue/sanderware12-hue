import os
import hashlib
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
import threading

# Globale Variablen für die Suche
ORDNER_PFAD = ""
DATEI_TYPEN = ('.pdf', '.calc', '.odt', '.jpg', '.raw')

# Funktion zur Hash-Berechnung (unverändert)
def datei_hash_berechnen(pfad, block_size=65536):
    """Berechnet den SHA-1-Hash einer Datei."""
    sha1 = hashlib.sha1()
    try:
        with open(pfad, 'rb') as f:
            while True:
                data = f.read(block_size)
                if not data:
                    break
                sha1.update(data)
        return sha1.hexdigest()
    except (IOError, PermissionError):
        return None

def doppelte_dateien_finden_thread():
    """Startet die Suche in einem separaten Thread, um die Benutzeroberfläche nicht zu blockieren."""
    ergebnis_text.delete(1.0, tk.END)
    ergebnis_text.insert(tk.END, "--- Suche gestartet ---\n")
    ergebnis_text.insert(tk.END, f"Durchsuche Ordner: {ORDNER_PFAD}\n")
    ergebnis_text.insert(tk.END, "Dies kann eine Weile dauern...\n\n")
    
    dateien_nach_groesse = {}
    dateien_gefunden = 0
    
    # Schritt 1: Dateien nach Größe und Datum gruppieren
    for root, _, files in os.walk(ORDNER_PFAD):
        for file in files:
            if not file.lower().endswith(DATEI_TYPEN):
                continue
            
            dateien_gefunden += 1
            file_path = os.path.join(root, file)
            
            try:
                file_size = os.path.getsize(file_path)
                file_mod_date = datetime.fromtimestamp(os.path.getmtime(file_path))
                
                if file_size not in dateien_nach_groesse:
                    dateien_nach_groesse[file_size] = []
                
                dateien_nach_groesse[file_size].append({
                    'pfad': file_path,
                    'datum': file_mod_date
                })
            except (IOError, PermissionError):
                continue
            
    doppelte_nach_hash = {}
    fortschritt_label.config(text="Phase 2: Hash-Werte berechnen...")

    # Schritt 2: Hash-Werte für potenzielle Duplikate berechnen
    potenzielle_duplikate_anzahl = sum(len(liste) for liste in dateien_nach_groesse.values() if len(liste) > 1)
    verarbeitete_dateien = 0
    
    for size, datei_liste in dateien_nach_groesse.items():
        if len(datei_liste) > 1:
            for i in range(len(datei_liste)):
                for j in range(i + 1, len(datei_liste)):
                    datei1 = datei_liste[i]
                    datei2 = datei_liste[j]

                    if datei1['datum'] == datei2['datum']:
                        hash1 = datei_hash_berechnen(datei1['pfad'])
                        hash2 = datei_hash_berechnen(datei2['pfad'])

                        if hash1 and hash2 and hash1 == hash2:
                            if hash1 not in doppelte_nach_hash:
                                doppelte_nach_hash[hash1] = []
                            
                            if datei1['pfad'] not in doppelte_nach_hash[hash1]:
                                doppelte_nach_hash[hash1].append(datei1['pfad'])
                            
                            if datei2['pfad'] not in doppelte_nach_hash[hash1]:
                                doppelte_nach_hash[hash1].append(datei2['pfad'])
            
            # Fortschritt aktualisieren
            verarbeitete_dateien += len(datei_liste)
            fortschritt_label.config(text=f"Phase 2: Verarbeite {verarbeitete_dateien}/{potenzielle_duplikate_anzahl} Dateien...")

    ergebnis_text.insert(tk.END, "\n--- Ergebnis ---\n")
    ergebnis_text.insert(tk.END, f"Insgesamt wurden {dateien_gefunden} Dateien durchsucht.\n")
    
    if not doppelte_nach_hash:
        ergebnis_text.insert(tk.END, "\nKeine doppelten Dateien gefunden.\n")
    else:
        ergebnis_text.insert(tk.END, f"\nEs wurden {len(doppelte_nach_hash)} Gruppen von doppelten Dateien gefunden.\n")
        for i, (hash_wert, pfade) in enumerate(doppelte_nach_hash.items()):
            ergebnis_text.insert(tk.END, f"\nGruppe {i + 1}:\n")
            for pfad in pfade:
                ergebnis_text.insert(tk.END, f"  - {pfad}\n")
        ergebnis_text.insert(tk.END, "\nBitte überprüfen Sie die Dateien manuell, um zu entscheiden, welche Sie behalten möchten.\n")
    
    fortschritt_label.config(text="Suche beendet.")

def starte_suche():
    """Startet die Suche, wenn der Ordner ausgewählt ist."""
    global ORDNER_PFAD
    if not ORDNER_PFAD:
        messagebox.showerror("Fehler", "Bitte wählen Sie zuerst einen Ordner aus.")
        return
    
    # Startet die Suche in einem separaten Thread
    suche_thread = threading.Thread(target=doppelte_dateien_finden_thread)
    suche_thread.start()

def ordner_auswaehlen():
    """Öffnet einen Dialog zur Auswahl eines Ordners."""
    global ORDNER_PFAD
    neuer_pfad = filedialog.askdirectory()
    if neuer_pfad:
        ORDNER_PFAD = neuer_pfad
        pfad_label.config(text=f"Ausgewählter Ordner: {ORDNER_PFAD}")
        ergebnis_text.delete(1.0, tk.END)
        ergebnis_text.insert(tk.END, f"Ordner '{ORDNER_PFAD}' ausgewählt. Klicken Sie auf 'Suche starten'.")

# Hauptfenster erstellen
root = tk.Tk()
root.title("Doppelte Dateien finden")
root.geometry("800x600")

# Widgets erstellen
haupt_frame = tk.Frame(root, padx=10, pady=10)
haupt_frame.pack(fill=tk.BOTH, expand=True)

titel_label = tk.Label(haupt_frame, text="Doppelte Dateien finden", font=("Arial", 16))
titel_label.pack(pady=5)

ordner_btn = tk.Button(haupt_frame, text="Ordner auswählen", command=ordner_auswaehlen)
ordner_btn.pack(pady=5)

pfad_label = tk.Label(haupt_frame, text="Ausgewählter Ordner: Keiner ausgewählt", wraplength=700)
pfad_label.pack(pady=5)

suche_btn = tk.Button(haupt_frame, text="Suche starten", command=starte_suche)
suche_btn.pack(pady=5)

fortschritt_label = tk.Label(haupt_frame, text="", fg="blue")
fortschritt_label.pack(pady=5)

ergebnis_label = tk.Label(haupt_frame, text="Ergebnisse:")
ergebnis_label.pack(pady=5)

ergebnis_text = scrolledtext.ScrolledText(haupt_frame, wrap=tk.WORD, width=90, height=20, font=("Courier", 10))
ergebnis_text.pack(fill=tk.BOTH, expand=True)

# Hauptfenster-Loop starten
root.mainloop()