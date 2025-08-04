# AES.py - Erweitertes Ver- und Entschlüsselungsprogramm mit 4 Feldern

import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import json
import random

# --- Globale Konstanten und GUI-Variablen ---

# Hauptfenster der GUI
root = tk.Tk()
root.title("AES Passwort Ver- & Entschlüsselung")
root.geometry("600x600") # Etwas größeres Fenster für mehr Felder

# --- Konstanten für AES ---
SALT_B64 = "L9PvHia+POi+62G8YWvWgg=="
SALT = base64.b64decode(SALT_B64)
PBKDF2_ITERATIONS = 100000
KEY_LENGTH = 32 # 32 Bytes = 256 Bit Schlüssel für AES-256

# --- GUI-Elemente ---

# 1. Feld: Original-Passwort (Eingabe)
tk.Label(root, text="Original-Passwort eingeben:").pack(pady=(10,0))
# Kein show="*" mehr, damit das Passwort sichtbar ist
entry_password_input = tk.Entry(root)
entry_password_input.pack(pady=5, padx=20, fill=tk.X)

# 2. Feld: Verschlüsselter Text (Ausgabe)
tk.Label(root, text="Verschlüsselter Text (Base64):").pack(pady=(10,0))
text_ciphertext_output = tk.Text(root, height=8, width=50, state='disabled') # Standardmäßig deaktiviert
text_ciphertext_output.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)

# 3. Feld: Entschlüsseltes Passwort (Ausgabe)
tk.Label(root, text="Entschlüsseltes Passwort:").pack(pady=(10,0))
text_decrypted_output = tk.Text(root, height=3, width=50, state='disabled') # Standardmäßig deaktiviert
text_decrypted_output.pack(pady=5, padx=20, fill=tk.X)

# 4. Feld: Status / Infos / Datum
tk.Label(root, text="Status / Verschlüsselungsdatum:").pack(pady=(10,0))
text_status_output = tk.Text(root, height=3, width=50, state='disabled') # Standardmäßig deaktiviert
text_status_output.pack(pady=5, padx=20, fill=tk.X)


# --- Dateiname für die Speicherung der verschlüsselten Daten ---
DATA_FILE = "encrypted_passwords.json"

# --- Hilfsfunktion zum Aktivieren/Deaktivieren und Setzen von Textfeldern ---
def set_text_field(text_widget, content):
    text_widget.config(state='normal') # Temporär aktivieren
    text_widget.delete(1.0, tk.END)
    text_widget.insert(tk.END, content)
    text_widget.config(state='disabled') # Wieder deaktivieren

# --- Funktionen ---

# Funktion zur Verschlüsselung des Passworts
def encrypt_password():
    password_str = entry_password_input.get()

    if not password_str:
        messagebox.showerror("Fehler", "Bitte ein Passwort zum Verschlüsseln eingeben!")
        return

    try:
        # 1. Schlüsselableitung
        key = PBKDF2(password_str.encode('utf-8'), SALT, dklen=KEY_LENGTH, count=PBKDF2_ITERATIONS)

        # 2. Generiere einen ZUFÄLLIGEN Initialisierungsvektor (IV) für jede Verschlüsselung
        iv = bytes(random.getrandbits(8) for _ in range(AES.block_size))

        # 3. AES Cipher Objekt erstellen
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # 4. Passwort padding und verschlüsseln
        padded_password_bytes = pad(password_str.encode('utf-8'), AES.block_size)
        ciphertext_bytes = cipher.encrypt(padded_password_bytes)

        # 5. Base64-Kodierung für Speicherung und Anzeige
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        # 6. Datum und Uhrzeit der Verschlüsselung
        current_date_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        # 7. Daten speichern (Chiffretext, IV, Datum) in einer JSON-Datei
        data_to_save = {
            "ciphertext_b64": ciphertext_b64,
            "iv_b64": iv_b64,
            "encryption_date": current_date_time
        }
        with open(DATA_FILE, 'w') as f:
            json.dump(data_to_save, f, indent=4)

        # 8. Ausgabe in den Textfeldern aktualisieren
        set_text_field(text_ciphertext_output, ciphertext_b64)
        set_text_field(text_decrypted_output, "") # Entschlüsseltes Feld leeren
        set_text_field(text_status_output, f"Verschlüsselt am: {current_date_time}")

        messagebox.showinfo("Erfolg", "Passwort verschlüsselt und gespeichert!")

    except Exception as e:
        messagebox.showerror("Fehler", f"Fehler bei der Verschlüsselung: {e}")

# Funktion zur Entschlüsselung des Passworts
def decrypt_password():
    password_str = entry_password_input.get() # Das eingegebene Passwort im ersten Feld verwenden

    if not password_str:
        messagebox.showerror("Fehler", "Bitte das GLEICHE Passwort zur Entschlüsselung eingeben!")
        return

    try:
        # 1. Daten aus der Datei laden
        with open(DATA_FILE, 'r') as f:
            loaded_data = json.load(f)

        ciphertext_b64 = loaded_data["ciphertext_b64"]
        iv_b64 = loaded_data["iv_b64"]
        encryption_date = loaded_data["encryption_date"]

        # 2. Base64-dekodieren
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)

        # 3. Schlüsselableitung (muss exakt GLEICH sein wie bei Verschlüsselung)
        key = PBKDF2(password_str.encode('utf-8'), SALT, dklen=KEY_LENGTH, count=PBKDF2_ITERATIONS)

        # 4. AES Cipher Objekt erstellen
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # 5. Entschlüsseln und unpad
        decrypted_password_bytes = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
        decrypted_password_str = decrypted_password_bytes.decode('utf-8')

        # 6. Ausgabe in den Textfeldern aktualisieren
        set_text_field(text_ciphertext_output, ciphertext_b64) # Chiffretext anzeigen
        set_text_field(text_decrypted_output, decrypted_password_str) # Entschlüsseltes Passwort anzeigen
        set_text_field(text_status_output, f"Verschlüsselt am: {encryption_date}\nEntschlüsselt: Erfolgreich")

        messagebox.showinfo("Erfolg", "Passwort entschlüsselt!")

    except FileNotFoundError:
        messagebox.showerror("Fehler", f"Keine verschlüsselten Daten gefunden. Datei '{DATA_FILE}' fehlt.")
        set_text_field(text_ciphertext_output, "")
        set_text_field(text_decrypted_output, "")
        set_text_field(text_status_output, "Fehler: Keine Daten zum Entschlüsseln.")
    except json.JSONDecodeError:
        messagebox.showerror("Fehler", f"Fehler beim Lesen der Daten aus '{DATA_FILE}'. Datei ist möglicherweise beschädigt.")
        set_text_field(text_ciphertext_output, "")
        set_text_field(text_decrypted_output, "")
        set_text_field(text_status_output, "Fehler: Datenformat fehlerhaft.")
    except ValueError as e:
        # Häufig bei fals 
        pass