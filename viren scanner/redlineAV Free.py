import os
import hashlib
import requests
import threading
from tkinter import *
from tkinter import messagebox, filedialog
from tkinter.ttk import Progressbar
from concurrent.futures import ThreadPoolExecutor, as_completed
from PIL import Image, ImageTk
import subprocess  # <- Neu: Zum Ports blockieren

# Konfiguration
HASH_DB = "virendatenbank.txt"
MAX_FILESIZE_MB = 100
VERDÄCHTIGE_ENDUNGEN = (".exe", ".dll", ".bat", ".scr", ".ps1")
VERTRAUENSWÜRDIGE_VERZEICHNISSE = [
    "C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)", "C:\\Users\\"
]

is_scanning = False
rotierendes_schild = None
schild_winkel = 0
schild_bild_original = None
schild_label = None

# Hilfsfunktionen
def lade_hashes():
    try:
        url = "https://bazaar.abuse.ch/export/txt/sha256/full/"
        response = requests.get(url)
        if response.status_code == 200:
            hashes = response.text.strip().splitlines()
            with open(HASH_DB, "w", encoding="utf-8", errors="ignore") as f:
                for h in hashes[:500]:
                    f.write(h + "\n")
    except Exception as e:
        print("Fehler beim Laden der Hashes:", e)

def lade_hash_datenbank():
    if not os.path.exists(HASH_DB):
        return set()
    with open(HASH_DB, "r", encoding="utf-8") as f:
        return set(line.strip() for line in f if line.strip())

def berechne_sha256(pfad):
    try:
        sha256 = hashlib.sha256()
        with open(pfad, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                sha256.update(block)
        return sha256.hexdigest()
    except:
        return None

def ist_vertrauenswürdig(dateipfad):
    for verzeichnis in VERTRAUENSWÜRDIGE_VERZEICHNISSE:
        if dateipfad.lower().startswith(verzeichnis.lower()):
            return True
    return False

def scanne_datei(datei, datenbank):
    try:
        if not datei.lower().endswith(VERDÄCHTIGE_ENDUNGEN):
            return None
        if os.path.getsize(datei) > MAX_FILESIZE_MB * 1024 * 1024:
            return None
        if ist_vertrauenswürdig(datei):
            return None
        hashwert = berechne_sha256(datei)
        if hashwert and hashwert in datenbank:
            return datei
    except:
        pass
    return None

def starte_schild_rotation():
    global schild_winkel, rotierendes_schild
    schild_winkel = 0
    def rotate():
        global schild_winkel
        if is_scanning:
            drehung = schild_bild_original.rotate(schild_winkel)
            schild_img = ImageTk.PhotoImage(drehung)
            schild_label.config(image=schild_img)
            schild_label.image = schild_img
            schild_winkel = (schild_winkel + 10) % 360
            root.after(100, rotate)
    rotate()

def führe_scan_durch(verzeichnisse, fortschritt_balken, button, modus_name):
    global is_scanning
    if is_scanning:
        return
    is_scanning = True
    threading.Thread(target=lambda: scan(verzeichnisse, fortschritt_balken, button, modus_name)).start()
    starte_schild_rotation()

def scan(verzeichnisse, fortschritt_balken, button, modus_name):
    button.config(state=DISABLED)
    fortschritt_balken["value"] = 0
    gefundene_viren.delete(0, END)

    status_label.config(text="Lade Malware-Datenbank...")
    lade_hashes()
    datenbank = lade_hash_datenbank()

    status_label.config(text="Sammle Dateien...")
    dateien = []
    for verzeichnis in verzeichnisse:
        for pfad, _, files in os.walk(verzeichnis):
            for file in files:
                pf = os.path.join(pfad, file)
                dateien.append(pf)

    gesamt = len(dateien)
    if gesamt == 0:
        status_label.config(text="Keine Dateien gefunden.")
        button.config(state=NORMAL)
        return

    status_label.config(text=f"{gesamt} Dateien gefunden. Scanne...")

    gefundene = []
    cpu_threads = max(2, os.cpu_count() - 1)

    def update_progress(i):
        fortschritt_balken["value"] = (i / gesamt) * 100
        root.update_idletasks()

    with ThreadPoolExecutor(max_workers=cpu_threads) as executor:
        futures = {executor.submit(scanne_datei, datei, datenbank): datei for datei in dateien}
        for i, future in enumerate(as_completed(futures)):
            result = future.result()
            if result:
                gefundene.append(result)
                gefundene_viren.insert(END, result)
            update_progress(i + 1)

    fortschritt_balken["value"] = 100
    status_label.config(text=f"Scan abgeschlossen – {len(gefundene)} Bedrohung(en) gefunden")
    if len(gefundene) > 0:
        messagebox.showwarning("Bedrohung erkannt", f"{len(gefundene)} Bedrohung(en) beim {modus_name} gefunden!")
    button.config(state=NORMAL)
    global is_scanning
    is_scanning = False

# Scan-Modi
def starte_smart_scan():
    verzeichnisse = [
        "C:\\Users",
        "C:\\Program Files",
        "C:\\Program Files (x86)",
        "C:\\Windows\\System32",
        "C:\\Windows\\SysWOW64",
    ]
    führe_scan_durch(verzeichnisse, fortschritt_smart, scan_button_smart, "Smart Scan")

def starte_komplett_scan():
    verzeichnisse = ["C:\\"]
    führe_scan_durch(verzeichnisse, fortschritt_komplett, scan_button_komplett, "Komplett Scan")

def starte_extremscan():
    verzeichnisse = [
        os.path.join(os.getenv("SystemRoot"), "System32"),
        os.path.join(os.getenv("SystemRoot"), "SysWOW64"),
        os.path.expanduser("~\\AppData\\Roaming"),
        os.path.expanduser("~\\AppData\\Local\\Temp")
    ]
    führe_scan_durch(verzeichnisse, fortschritt_extrem, scan_button_extrem, "Extrem Scan")

def starte_benutzerdefiniert_scan():
    ordner = filedialog.askdirectory(title="Ordner für Scan auswählen")
    if ordner:
        führe_scan_durch([ordner], fortschritt_custom, scan_button_custom, "Benutzerdefinierter Scan")

def starte_ultra_deep_scan():
    verzeichnisse = ["C:\\"]
    führe_scan_durch(verzeichnisse, fortschritt_ultra, scan_button_ultra, "Ultra Deep Scan")

# Junk Cleaner
def junk_cleaner_fenster():
    junk_win = Toplevel(root)
    junk_win.title("Junk Cleaner")
    junk_win.geometry("600x400")
    junk_win.configure(bg="#330000")

    junk_progress = Progressbar(junk_win, orient=HORIZONTAL, length=500, mode='determinate')
    junk_progress.pack(pady=20)

    junk_status = Label(junk_win, text="", fg="white", bg="#330000")
    junk_status.pack()

    def starte_clean():
        threading.Thread(target=lambda: clean(junk_progress, junk_status)).start()

    Button(junk_win, text="Junk-Dateien bereinigen", command=starte_clean, bg="red", fg="white").pack(pady=10)

def clean(fortschritt, status):
    junk_ordner = [
        os.getenv('TEMP'),
        os.path.join(os.getenv('SystemRoot'), 'Temp'),
        os.path.join(os.getenv('LOCALAPPDATA'), 'Temp'),
    ]
    gesamt_junk_dateien = []
    for ordner in junk_ordner:
        for pfad, _, files in os.walk(ordner):
            for file in files:
                gesamt_junk_dateien.append(os.path.join(pfad, file))

    gesamt = len(gesamt_junk_dateien)
    if gesamt == 0:
        status.config(text="Keine Junk-Dateien gefunden.")
        return

    gesamt_bytes = 0
    for i, datei in enumerate(gesamt_junk_dateien):
        try:
            if os.path.exists(datei):
                size = os.path.getsize(datei)
                gesamt_bytes += size
                os.remove(datei)
        except:
            continue
        fortschritt["value"] = (i / gesamt) * 100
        root.update_idletasks()

    mb = gesamt_bytes / (1024 * 1024)
    status.config(text=f"Junk Cleaning abgeschlossen – {mb:.2f} MB entfernt")

# --- NEU: Port Blockieren Funktion ---
def port_blockieren_fenster():
    port_win = Toplevel(root)
    port_win.title("Port blockieren")
    port_win.geometry("400x200")
    port_win.configure(bg="#330000")

    Label(port_win, text="Portnummer eingeben:", bg="#330000", fg="white", font=("Arial", 12)).pack(pady=10)
    port_entry = Entry(port_win)
    port_entry.pack(pady=5)

    def blockiere_port():
        port = port_entry.get()
        if port.isdigit():
            try:
                rule_name = f"Block Port {port}"
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                "name=" + rule_name, "dir=in", "action=block", "protocol=TCP", "localport=" + port], check=True)
                subprocess.run(["netsh", "advfirewall", "firewall", "add", "rule",
                                "name=" + rule_name, "dir=out", "action=block", "protocol=TCP", "localport=" + port], check=True)
                messagebox.showinfo("Erfolg", f"Port {port} wurde blockiert.")
                port_win.destroy()
            except Exception as e:
                messagebox.showerror("Fehler", f"Port konnte nicht blockiert werden: {e}")
        else:
            messagebox.showwarning("Ungültig", "Bitte eine gültige Portnummer eingeben.")

    Button(port_win, text="Blockieren", command=blockiere_port, bg="red", fg="white").pack(pady=20)
# --- Ende NEU ---

# GUI
root = Tk()
root.title("Redline - Anti-Malware & Junk Cleaner")
root.attributes('-fullscreen', True)
root.configure(bg="#330000")

# App-Logo setzen
app_logo = PhotoImage(file="app_logo.png")
root.iconphoto(False, app_logo)

# Layout
left_frame = Frame(root, bg="#330000")
left_frame.pack(side=LEFT, fill=BOTH, expand=True)

right_frame = Frame(root, bg="#550000", width=300)
right_frame.pack(side=RIGHT, fill=Y)

# Schild laden
schild_bild_original = Image.open("schild.png").resize((100, 100))
schild_img = ImageTk.PhotoImage(schild_bild_original)
schild_label = Label(left_frame, image=schild_img, bg="#330000")
schild_label.pack(pady=10)

# Gefundene Viren
Label(left_frame, text="Gefundene Viren:", fg="white", bg="#330000", font=("Arial", 12)).pack()
gefundene_viren = Listbox(left_frame, width=90, bg="#660000", fg="white")
gefundene_viren.pack(pady=10, fill=BOTH, expand=True)

status_label = Label(left_frame, text="", fg="white", bg="#330000", font=("Arial", 10))
status_label.pack(pady=10)

# Scan Buttons
Label(right_frame, text="Scanning", font=("Arial", 14, "bold"), fg="white", bg="#550000").pack(pady=10)

fortschritt_smart = Progressbar(right_frame, orient=HORIZONTAL, length=200, mode='determinate')
fortschritt_smart.pack(pady=5)
scan_button_smart = Button(right_frame, text="Smart Scan", command=starte_smart_scan, bg="red", fg="white")
scan_button_smart.pack(pady=5)

fortschritt_komplett = Progressbar(right_frame, orient=HORIZONTAL, length=200, mode='determinate')
fortschritt_komplett.pack(pady=5)
scan_button_komplett = Button(right_frame, text="Komplett Scan", command=starte_komplett_scan, bg="red", fg="white")
scan_button_komplett.pack(pady=5)

fortschritt_extrem = Progressbar(right_frame, orient=HORIZONTAL, length=200, mode='determinate')
fortschritt_extrem.pack(pady=5)
scan_button_extrem = Button(right_frame, text="Extrem Scan", command=starte_extremscan, bg="red", fg="white")
scan_button_extrem.pack(pady=5)

fortschritt_custom = Progressbar(right_frame, orient=HORIZONTAL, length=200, mode='determinate')
fortschritt_custom.pack(pady=5)
scan_button_custom = Button(right_frame, text="Benutzerdefinierter Scan", command=starte_benutzerdefiniert_scan, bg="red", fg="white")
scan_button_custom.pack(pady=5)

fortschritt_ultra = Progressbar(right_frame, orient=HORIZONTAL, length=200, mode='determinate')
fortschritt_ultra.pack(pady=5)
scan_button_ultra = Button(right_frame, text="Ultra Deep Scan", command=starte_ultra_deep_scan, bg="red", fg="white")
scan_button_ultra.pack(pady=5)

Button(right_frame, text="Junk Cleaner", command=junk_cleaner_fenster, bg="darkred", fg="white", font=("Arial", 10)).pack(pady=20)

# --- NEU: Port Blockier-Button ---
Button(right_frame, text="Port blockieren", command=port_blockieren_fenster, bg="darkred", fg="white", font=("Arial", 10)).pack(pady=10)
# --- Ende NEU ---

root.mainloop()
