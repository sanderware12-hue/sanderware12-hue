import tkinter as tk
import psutil
import time
import threading
import os
import shutil
from tkinter import messagebox, filedialog

# Globale Variablen
root = None
selected_partition = None
log_text_widget = None

# Pfad zum Ordner mit den simulierten verlorenen Dateien
VERLORENE_DATEIEN_PFAD = "verlorene_dateien"


# Funktion zum Abrufen der Festplatteninformationen
def get_disk_info():
    partitions = psutil.disk_partitions()
    disk_info = []
    for partition in partitions:
        try:
            usage = psutil.disk_usage(partition.mountpoint)
            disk_info.append(
                {
                    "device": partition.device,
                    "total": usage.total,
                    "used": usage.used,
                    "free": usage.free,
                    "percent": usage.percent,
                }
            )
        except Exception:
            disk_info.append(
                {
                    "device": partition.device,
                    "total": 0,
                    "used": 0,
                    "free": 0,
                    "percent": 0,
                    "error": "Keine Informationen verfügbar",
                }
            )
    return disk_info


def on_select_button_click(device):
    global selected_partition
    selected_partition = device

    for widget in root.winfo_children():
        widget.destroy()

    show_selected_partition_gui()


def show_selected_partition_gui():
    global selected_partition
    title_frame = tk.Frame(root, bg="white", pady=10)
    title_frame.pack(fill="x")

    title_label = tk.Label(
        title_frame,
        text=f"Partition {selected_partition} wurde ausgewählt",
        font=("Helvetica", 16),
        bg="white",
    )
    title_label.pack()

    scan_button = tk.Button(
        root,
        text="Scannen nach verlorenen Partitionen",
        command=lambda: threading.Thread(target=run_scan).start(),
    )
    scan_button.pack(pady=10)

    back_button = tk.Button(root, text="Zurück zur Übersicht", command=create_gui)
    back_button.pack(pady=10)


def update_log_and_progress(log_message, progress_value=None, progress_label=None):
    global log_text_widget, root
    if log_text_widget:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_text_widget.config(state=tk.NORMAL)
        log_text_widget.insert(tk.END, f"[{timestamp}] {log_message}\n")
        log_text_widget.see(tk.END)
        log_text_widget.config(state=tk.DISABLED)

    if progress_value is not None and progress_label is not None:
        progress_label.config(text=f"{progress_value}%")

    root.update_idletasks()


def run_scan():
    global root, log_text_widget

    for widget in root.winfo_children():
        widget.destroy()

    scan_frame = tk.Frame(root, bg="white", pady=10)
    scan_frame.pack(fill="both", expand=True)

    scan_label = tk.Label(
        scan_frame,
        text=f"Scanne Partition {selected_partition}...",
        font=("Helvetica", 16),
        bg="white",
    )
    scan_label.pack(pady=10)

    progress_label = tk.Label(scan_frame, text="0%", font=("Helvetica", 12), bg="white")
    progress_label.pack(pady=5)

    log_text_widget = tk.Text(scan_frame, height=10)
    log_text_widget.pack(fill="both", expand=True, padx=10, pady=10)
    log_text_widget.config(state=tk.DISABLED)

    update_log_and_progress(f"Scan gestartet auf {selected_partition}")

    found_files = {}
    if os.path.exists(VERLORENE_DATEIEN_PFAD):
        for dirpath, dirnames, filenames in os.walk(VERLORENE_DATEIEN_PFAD):
            for file in filenames:
                file_path = os.path.join(dirpath, file)

                if file.endswith((".doc", ".docx", ".odt")):
                    file_type = "Dokumente (MS Office/OpenOffice)"
                elif file.endswith((".jpg", ".png", ".gif")):
                    file_type = "Bilder"
                elif file.endswith((".xlsx", ".ods")):
                    file_type = "Tabellen (MS Office/OpenOffice)"
                else:
                    file_type = "Sonstiges"

                if file_type not in found_files:
                    found_files[file_type] = []
                found_files[file_type].append(file)
    else:
        update_log_and_progress(
            f"Fehler: Ordner '{VERLORENE_DATEIEN_PFAD}' nicht gefunden."
        )

    for i in range(101):
        if i % 10 == 0:
            update_log_and_progress(
                f"Überprüfe Sektor {i * 1000}-{i * 1000 + 999}", i, progress_label
            )
        time.sleep(0.01)

    update_log_and_progress("Scan abgeschlossen")

    root.after(1000, show_scan_results, found_files)


def show_scan_results(found_files):
    global root

    for widget in root.winfo_children():
        widget.destroy()

    title_frame = tk.Frame(root, bg="white", pady=10)
    title_frame.pack(fill="x")
    title_label = tk.Label(
        title_frame, text="Gefundene Dateien", font=("Helvetica", 16), bg="white"
    )
    title_label.pack()

    files_to_recover = {}

    for file_type, files in found_files.items():
        type_label = tk.Label(
            root, text=file_type, font=("Helvetica", 14, "bold"), bg="white"
        )
        type_label.pack(fill="x", padx=10, pady=(10, 0))

        for file in files:
            file_frame = tk.Frame(root, bg="lightgrey", padx=10, pady=5)
            file_frame.pack(fill="x", pady=2)

            var = tk.BooleanVar(value=True)
            files_to_recover[file] = var

            file_checkbutton = tk.Checkbutton(
                file_frame, text=file, variable=var, bg="lightgrey"
            )
            file_checkbutton.pack(side="left")

    recover_button = tk.Button(
        root,
        text="Ausgewählte wiederherstellen",
        command=lambda: threading.Thread(
            target=restore_files_and_show_progress, args=(files_to_recover,)
        ).start(),
    )
    recover_button.pack(pady=10)

    back_button = tk.Button(root, text="Zurück zur Übersicht", command=create_gui)
    back_button.pack(pady=10)


def restore_files_and_show_progress(files_to_recover):
    global root

    restore_path = filedialog.askdirectory(
        title="Wähle den Speicherort für die wiederhergestellten Dateien"
    )
    if not restore_path:
        return

    recovery_window = tk.Toplevel(root)
    recovery_window.title("Dateien wiederherstellen")

    label = tk.Label(
        recovery_window,
        text=f"Stelle Dateien nach {restore_path} wieder her...",
        font=("Helvetica", 12),
    )
    label.pack(pady=10)

    progress_label = tk.Label(recovery_window, text="0%", font=("Helvetica", 12))
    progress_label.pack(pady=5)

    progress_bar = tk.Canvas(
        recovery_window, width=400, height=20, bg="white", highlightthickness=1
    )
    progress_bar.pack(pady=5)

    selected_files = [
        filename for filename, var in files_to_recover.items() if var.get()
    ]
    total_files = len(selected_files)

    def update_progress():
        files_copied_count = 0
        for i, filename in enumerate(selected_files):
            try:
                source_path = ""
                for root_dir, dirs, files in os.walk(VERLORENE_DATEIEN_PFAD):
                    if filename in files:
                        source_path = os.path.join(root_dir, filename)
                        break

                if source_path:
                    base_name, extension = os.path.splitext(filename)
                    destination_filename = filename
                    counter = 1
                    while os.path.exists(
                        os.path.join(restore_path, destination_filename)
                    ):
                        destination_filename = f"{base_name}_Kopie{counter}{extension}"
                        counter += 1

                    shutil.copy(
                        source_path, os.path.join(restore_path, destination_filename)
                    )
                    files_copied_count += 1

                progress = (i + 1) / total_files * 100

                progress_bar.delete("all")
                width = (progress / 100) * 400
                progress_bar.create_rectangle(0, 0, width, 20, fill="green")

                progress_label.config(
                    text=f"Stelle '{filename}' wieder her... {int(progress)}%"
                )

            except Exception as e:
                progress_label.config(
                    text=f"Fehler bei der Wiederherstellung von {filename}: {e}"
                )

            root.update_idletasks()
            time.sleep(0.1)

        label.config(text="Wiederherstellung abgeschlossen!")
        progress_label.config(
            text=f"Insgesamt wurden {files_copied_count} Dateien wiederhergestellt."
        )

        # Schließe das Fenster nach 3 Sekunden
        root.after(3000, recovery_window.destroy)

    if selected_files:
        threading.Thread(target=update_progress).start()
    else:
        messagebox.showwarning(
            "Keine Auswahl",
            "Bitte wähle mindestens eine Datei zur Wiederherstellung aus.",
        )
        recovery_window.destroy()


def create_gui():
    global root
    for widget in root.winfo_children():
        widget.destroy()

    title_frame = tk.Frame(root, bg="white", pady=10)
    title_frame.pack(fill="x")

    title_label = tk.Label(
        title_frame,
        text="Festplatten und Partitionen",
        font=("Helvetica", 16),
        bg="white",
    )
    title_label.pack()

    disk_info = get_disk_info()

    for info in disk_info:
        frame = tk.Frame(root, bg="white", padx=10, pady=5)
        frame.pack(fill="x")

        device_label = tk.Label(
            frame,
            text=f"Laufwerk: {info['device']} ({info['total'] / (1024**3):.2f} GB)",
            bg="white",
        )
        device_label.pack(side="left")

        select_button = tk.Button(
            frame,
            text="Auswählen",
            command=lambda device=info["device"]: on_select_button_click(device),
        )
        select_button.pack(side="right", padx=10)

        if "error" in info:
            error_label = tk.Label(frame, text=info["error"], bg="white", fg="red")
            error_label.pack(side="right")
        else:
            percentage = int(info["percent"])
            occupied_width = (percentage / 100) * 500

            canvas = tk.Canvas(
                frame, width=500, height=20, bg="white", highlightthickness=0
            )
            canvas.pack(side="right", padx=5)

            canvas.create_rectangle(0, 0, 500, 20, outline="black", fill="white")
            canvas.create_rectangle(
                0, 0, occupied_width, 20, outline="black", fill="green"
            )
            canvas.create_text(
                occupied_width / 2, 10, text=f"{percentage}%", fill="black"
            )


if __name__ == "__main__":
    if not os.path.exists(VERLORENE_DATEIEN_PFAD):
        os.makedirs(os.path.join(VERLORENE_DATEIEN_PFAD, "Dokumente"))
        os.makedirs(os.path.join(VERLORENE_DATEIEN_PFAD, "Bilder"))
        os.makedirs(os.path.join(VERLORENE_DATEIEN_PFAD, "Tabellen"))
        os.makedirs(os.path.join(VERLORENE_DATEIEN_PFAD, "Sonstiges"))

        with open(
            os.path.join(VERLORENE_DATEIEN_PFAD, "Dokumente", "Bericht.docx"), "w"
        ) as f:
            f.write("Dies ist ein Word-Dokument.")
        with open(
            os.path.join(VERLORENE_DATEIEN_PFAD, "Dokumente", "Notiz.odt"), "w"
        ) as f:
            f.write("Dies ist ein OpenOffice-Dokument.")
        with open(os.path.join(VERLORENE_DATEIEN_PFAD, "Bilder", "logo.jpg"), "w") as f:
            f.write("Dies ist ein simuliertes Bild.")
        with open(
            os.path.join(VERLORENE_DATEIEN_PFAD, "Tabellen", "Daten.ods"), "w"
        ) as f:
            f.write("Dies ist eine simulierte OpenOffice-Tabelle.")

    root = tk.Tk()
    create_gui()
    root.mainloop()
