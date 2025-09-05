import tkinter as tk
from tkinter import messagebox
import base64
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

# Globale Konstanten
PBKDF2_ITERATIONS = 100000
KEY_LENGTH = 32  # 256 bits = 32 bytes

# Hauptfenster
root = tk.Tk()
root.title("AES-256 Verschlüsselung v10.0")
root.geometry("600x350")

# Widgets erstellen
label_key = tk.Label(root, text="Schlüsselpasswort:")
entry_key = tk.Entry(root, show="*")

label_date = tk.Label(root, text="Datum (DD.MM.YYYY):")
entry_date = tk.Entry(root)
entry_date.insert(0, datetime.now().strftime("%d.%m.%Y"))

label_plaintext = tk.Label(root, text="Text zum Verschlüsseln:")
entry_plaintext = tk.Entry(root)

label_ciphertext = tk.Label(root, text="Verschlüsselter Text:")
entry_ciphertext = tk.Entry(root)


# Funktionen
def is_valid_date(date_str):
    try:
        datetime.strptime(date_str, "%d.%m.%Y")
        return True
    except ValueError:
        return False


def derive_key_with_date(password, date_str):
    salt_with_date = b"L9PvHia+POi+62G8YWvWgg==" + date_str.encode("utf-8")
    return PBKDF2(
        password.encode("utf-8"),
        salt_with_date,
        dkLen=KEY_LENGTH,
        count=PBKDF2_ITERATIONS,
    )


def encrypt_text():
    password = entry_key.get()
    date_str = entry_date.get()
    plaintext = entry_plaintext.get()

    if not is_valid_date(date_str):
        messagebox.showerror(
            "Fehler", "Falsches Datum. Bitte verwenden Sie das Format DD.MM.YYYY."
        )
        return

    if not password or not plaintext:
        messagebox.showerror(
            "Fehler", "Schlüsselpasswort und Text dürfen nicht leer sein."
        )
        return

    try:
        key = derive_key_with_date(password, date_str)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(
            pad(plaintext.encode("utf-8"), AES.block_size)
        )

        entry_ciphertext.delete(0, tk.END)
        entry_ciphertext.insert(
            0, base64.b64encode(cipher.nonce + tag + ciphertext).decode("utf-8")
        )

    except Exception as e:
        messagebox.showerror("Fehler", f"Fehler bei der Verschlüsselung: {e}")


def decrypt_text():
    password = entry_key.get()
    date_str = entry_date.get()
    ciphertext_b64 = entry_ciphertext.get()

    if not is_valid_date(date_str):
        messagebox.showerror(
            "Fehler", "Falsches Datum. Bitte verwenden Sie das Format DD.MM.YYYY."
        )
        return

    if not password or not ciphertext_b64:
        messagebox.showerror(
            "Fehler",
            "Schlüsselpasswort und verschlüsselter Text dürfen nicht leer sein.",
        )
        return

    try:
        ciphertext_bytes = base64.b64decode(ciphertext_b64)
        nonce = ciphertext_bytes[:16]
        tag = ciphertext_bytes[16:32]
        ciphertext = ciphertext_bytes[32:]

        key = derive_key_with_date(password, date_str)
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        decrypted_bytes = unpad(
            cipher.decrypt_and_verify(ciphertext, tag), AES.block_size
        )

        messagebox.showinfo(
            "Erfolg", f"Entschlüsselter Text: {decrypted_bytes.decode('utf-8')}"
        )

    except Exception as e:
        messagebox.showerror("Fehler", f"Fehler bei der Entschlüsselung: {e}")


# Rechtsklick-Menü
def create_context_menu(widget):
    menu = tk.Menu(widget, tearoff=0)
    menu.add_command(
        label="Ausschneiden", command=lambda: widget.event_generate("<<Cut>>")
    )
    menu.add_command(
        label="Kopieren", command=lambda: widget.event_generate("<<Copy>>")
    )
    menu.add_command(
        label="Einfügen", command=lambda: widget.event_generate("<<Paste>>")
    )
    widget.bind("<Button-3>", lambda event: menu.tk_popup(event.x_root, event.y_root))


create_context_menu(entry_key)
create_context_menu(entry_date)
create_context_menu(entry_plaintext)
create_context_menu(entry_ciphertext)

# Platzierung der Widgets
label_key.pack(pady=5)
entry_key.pack(pady=5, padx=20, fill=tk.X)
label_date.pack(pady=5)
entry_date.pack(pady=5, padx=20, fill=tk.X)
label_plaintext.pack(pady=5)
entry_plaintext.pack(pady=5, padx=20, fill=tk.X)
label_ciphertext.pack(pady=5)
entry_ciphertext.pack(pady=5, padx=20, fill=tk.X)

button_frame = tk.Frame(root)
button_frame.pack(pady=10)
button_encrypt = tk.Button(button_frame, text="Verschlüsseln", command=encrypt_text)
button_encrypt.pack(side=tk.LEFT, padx=10)
button_decrypt = tk.Button(button_frame, text="Entschlüsseln", command=decrypt_text)
button_decrypt.pack(side=tk.LEFT, padx=10)

root.mainloop()
