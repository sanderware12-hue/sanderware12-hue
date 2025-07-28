import random
import string
import tkinter as tk
from tkinter import messagebox
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
import base64

# Funktion zur Generierung eines sicheren, zufälligen Passworts
def generate_secure_password(length=30):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choices(characters, k=length))

# Funktion zur Verschlüsselung des sicheren Passworts
def encrypt_password():
    try:
        password = entry_password.get()

        if not password:
            messagebox.showerror("Fehler", "Bitte ein Passwort eingeben!")
            return

        # Sicherstellen, dass das Passwort auf ein Vielfaches von 16 Bytes gepolstert ist
        while len(password) % 16 != 0:
            password += ' '  # Füge Leerzeichen hinzu, um das Passwort auf ein Vielfaches von 16 zu bringen

        salt_b64 = "L9pVh1a+PoI+62g8YWyWGg=="
        iv_b64 = "Z6H0N3g7w3HV6MN/OlK6YQ=="
        salt = base64.b64decode(salt_b64)
        iv = base64.b64decode(iv_b64)

        key = PBKDF2(password, salt, dkLen=32, count=100000)
        cipher = AES.new(key, AES.MODE_CBC, iv)

        # Verschlüsselung
        ciphertext = cipher.encrypt(password.encode('utf-8'))
        ciphertext_b64 = base64.b64encode(ciphertext).decode('utf-8')

        current_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        text_ciphertext.delete(1.0, tk.END)
        text_ciphertext._
