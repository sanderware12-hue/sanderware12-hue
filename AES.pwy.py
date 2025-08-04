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
root.geometry("600x700")  # Etwas größeres Fenster für 5 Felder

# --- Konstanten für AES ---
SALT_B64 = "L9PvHia+POi+62G8YWvWgg=="
SALT = base64.b64decode(SALT_B64)
PBKDF2_ITERATIONS = 100000
KEY_LENGTH = 32  # 32 Bytes = 256 Bit Schlüssel für AES-256

# --- GUI-Elemente ---

# 1. Feld: Original-Passwort (Eingabe)
tk.Label(root, text="Schlüsselpasswort für Ver- und Entschlüsselung:").pack(pady=(10, 0))
entry_password_input = tk.Entry(root)
entry_password_input.pack(pady=5, padx=20, fill=tk.X)

# 2. Feld: Text zum Verschlüsseln (Eingabe)
tk.Label(root, text="Text zum Verschlüsseln eingeben:").pack(pady=(10, 0))
text_plaintext_input = tk.Text(root, height=5, width=50)
text_plaintext_input.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)

# 3. Feld: Verschlüsselter Text (Ausgabe)
tk.Label(root, text="Verschlüsselter Text (Base64-Ausgabe):").pack(pady=(10, 0))
text_ciphertext_output = tk.Text(root, height=8, width=50, state='disabled')  # Standardmäßig deaktiviert
text_ciphertext_output.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)

# --- NEUES FELD für die Entschlüsselung ---
# 4. Feld: Verschlüsselter Text zum Entschlüsseln (Eingabe)
tk.Label(root, text="Verschlüsselten Text zum Entschlüsseln hier einfügen:").pack(pady=(10, 0))
text_decrypt_input = tk.Text(root, height=8, width=50)
text_decrypt_input.pack(pady=5, padx=20, fill=tk.BOTH, expand=True)

# 5. Feld: Entschlüsseltes Passwort (Ausgabe)
tk.Label(root, text="Entschlüsseltes Ergebnis:").pack(pady=(10, 0))
text_decrypted_output = tk.Text(root, height=3, width=50, state='disabled')  # Standardmäßig deaktiviert
text_decrypted_output.pack(pady=5, padx=20, fill=tk.X)


# --- Hilfsfunktion zum Aktivieren/Deaktivieren und Setzen von Textfeldern ---
def set_text_field(text_widget, content):
    text_widget.config(state='normal')  # Temporär aktivieren
    text_widget.delete(1.0, tk.END)
    text_widget.insert(tk.END, content)
    text_widget.config(state='disabled')  # Wieder deaktivieren

# --- Funktionen ---

# Funktion zur Verschlüsselung des Passworts
def encrypt_text():
    password_str = entry_password_input.get()
    plaintext_str = text_plaintext_input.get("1.0", tk.END).strip()

    if not password_str or not plaintext_str:
        messagebox.showerror("Fehler", "Bitte einen Schlüssel und Text zum Verschlüsseln eingeben!")
        return

    try:
        # 1. Schlüsselableitung
        key = PBKDF2(password_str.encode('utf-8'), SALT, dklen=KEY_LENGTH, count=PBKDF2_ITERATIONS)
        # 2. Generiere einen ZUFÄLLIGEN Initialisierungsvektor (IV) für jede Verschlüsselung
        iv = bytes(random.getrandbits(8) for _ in range(AES.block_size))
        # 3. AES Cipher Objekt erstellen
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # 4. Text padding und verschlüsseln
        padded_bytes = pad(plaintext_str.encode('utf-8'), AES.block_size)
        ciphertext_bytes = cipher.encrypt(padded_bytes)
        # 5. Base64-Kodierung für Speicherung und Anzeige
        ciphertext_b64 = base64.b64encode(ciphertext_bytes).decode('utf-8')
        iv_b64 = base64.b64encode(iv).decode('utf-8')

        # 6. Ausgabe in den Textfeldern aktualisieren (Chiffretext, IV, Datum)
        set_text_field(text_ciphertext_output, f"{ciphertext_b64}:{iv_b64}")
        set_text_field(text_decrypted_output, "")  # Entschlüsseltes Feld leeren

        messagebox.showinfo("Erfolg", "Text verschlüsselt! Kopieren Sie den verschlüsselten Text.")

    except Exception as e:
        messagebox.showerror("Fehler", f"Fehler bei der Verschlüsselung: {e}")

# Funktion zur Entschlüsselung des Passworts
def decrypt_text():
    password_str = entry_password_input.get()  # Das eingegebene Passwort im ersten Feld verwenden
    ciphertext_iv_b64 = text_decrypt_input.get("1.0", tk.END).strip()

    if not password_str or not ciphertext_iv_b64:
        messagebox.showerror("Fehler", "Bitte einen Schlüssel und den verschlüsselten Text eingeben!")
        return

    try:
        # 1. Trenne Chiffretext und IV
        parts = ciphertext_iv_b64.split(':')
        if len(parts) != 2:
            raise ValueError("Ungültiges Format des verschlüsselten Textes. Erwartet: ciphertext:iv")
        
        ciphertext_b64, iv_b64 = parts
        
        # 2. Base64-dekodieren
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        iv = base64.b64decode(iv_b64)

        # 3. Schlüsselableitung
        key = PBKDF2(password_str.encode('utf-8'), SALT, dklen=KEY_LENGTH, count=PBKDF2_ITERATIONS)

        # 4. AES Cipher Objekt erstellen
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # 5. Entschlüsseln und unpad
        decrypted_bytes = unpad(cipher.decrypt(ciphertext_bytes), AES.block_size)
        decrypted_str = decrypted_bytes.decode('utf-8')

        # 6. Ausgabe in den Textfeldern aktualisieren
        set_text_field(text_decrypted_output, decrypted_str)  # Entschlüsseltes Passwort anzeigen

        messagebox.showinfo("Erfolg", "Text entschlüsselt!")

    except Exception as e:
        messagebox.showerror("Fehler", f"Fehler bei der Entschlüsselung: {e}")
        set_text_field(text_decrypted_output, "Fehler bei der Entschlüsselung. Falsches Passwort oder Text?")


# --- Buttons zur Steuerung ---
button_frame = tk.Frame(root)
button_frame.pack(pady=10)

button_encrypt = tk.Button(button_frame, text="Verschlüsseln", command=encrypt_text)
button_encrypt.pack(side=tk.LEFT, padx=10)

button_decrypt = tk.Button(button_frame, text="Entschlüsseln", command=decrypt_text)
button_decrypt.pack(side=tk.LEFT, padx=10)

# --- Hauptschleife der GUI starten ---
root.mainloop()