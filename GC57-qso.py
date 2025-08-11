import tkinter as tk
from tkinter import filedialog, messagebox
import os
import random
import hashlib
from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import gcd
import win32api

# === CONFIGURAZIONE AVVIO ===
CFG_FILE = "QSOcfg"

if not os.path.exists(CFG_FILE):

    def chiudi_programma():
        risposta = messagebox.askquestion("Attenzione:", "uscire dal programma?")
        if risposta == "yes":
            rootcfg.destroy()
            quit()

    def normalizza_percorso(percorso):
        percorso = percorso.replace("\\", "/")
        if not percorso.endswith("/"):
            percorso += "/"
        return percorso

    def salva_esci():
        controlli = [e2_cfg, e3_cfg, e4_cfg, e5_cfg, e6_cfg]
        etichette = [
            "Cartella INVIO",
            "Cartella RICEVE",
            "Cartella ALLEGATI",
            "Cartella SEMIPRIMI",
            "Nome PenDrive",
        ]

        for idx, entry in enumerate(controlli[:-1]):
            percorso = entry.get().strip()
            if percorso == "" or not os.path.exists(percorso):
                messagebox.showerror(
                    "Attenzione:", f"{etichette[idx]} non valida o inesistente"
                )
                return

        if controlli[-1].get() == "":
            messagebox.showerror("Attenzione:", "Manca il nome PenDrive")
            return

        with open(CFG_FILE, "w") as f:
            for entry in controlli[:-1]:
                percorso_norm = normalizza_percorso(entry.get().strip())
                f.write(percorso_norm + "\n")
            f.write(controlli[-1].get().strip().upper() + "\n")

        messagebox.showinfo("Salvataggi CFG:", "Configurazione Salvata")
        rootcfg.destroy()

    rootcfg = tk.Tk()
    rootcfg.title("Configurazione Cartelle GC57")
    rootcfg.configure(bg="#458B74")
    rootcfg.geometry("415x480")

    testo = """Se appare questa finestra è perché il programma viene eseguito per la prima volta in questa posizione, 
oppure il file 'QSOcfg' è stato cancellato.

Copiare e incollare con CTRL+V la posizione delle cartelle:"""

    tk.Label(
        rootcfg,
        text=testo,
        justify=tk.LEFT,
        font="arial 12 bold",
        wraplength=400,
        bg="#458B74",
    ).place(x=10, y=20)

    labels = [
        "Incollare Indirizzo Cartella INVIO",
        "Incollare Indirizzo Cartella RICEVE",
        "Incollare Indirizzo Cartella ALLEGATI",
        "Incollare Indirizzo Cartella SEMIPRIMI",
        "Inserire il nome della PenDrive (Chiavi)",
    ]

    entries = []
    py = 180
    for label_text in labels:
        tk.Label(rootcfg, text=label_text, bg="#458B74", font="arial 12 bold").place(
            x=10, y=py
        )
        py += 20
        entry = tk.Entry(rootcfg, width=40, fg="#104E8B", font="arial 12")
        entry.place(x=10, y=py)
        entries.append(entry)
        py += 30

    e2_cfg, e3_cfg, e4_cfg, e5_cfg, e6_cfg = entries

    tk.Button(
        rootcfg,
        text="Salva ed Esci",
        font="arial 12 bold",
        cursor="hand1",
        bg="green",
        command=salva_esci,
    ).place(x=150, y=py)
    rootcfg.protocol("WM_DELETE_WINDOW", chiudi_programma)
    rootcfg.mainloop()

# === Carica le cartelle dal file CFG ===
with open(CFG_FILE, "r") as cfg:
    DIR_INVIATI = cfg.readline().strip().replace("\\", "/")
    DIR_RICEVUTI = cfg.readline().strip().replace("\\", "/")
    DIR_ALLEGATI = cfg.readline().strip().replace("\\", "/")
    DIR_SEMIPRIMI = cfg.readline().strip().replace("\\", "/")
    USB_LABEL = cfg.readline().strip().upper()

messagebox.showinfo("USB", "Inserisci la pen drive con il nome: " + USB_LABEL)


def get_drive_letter_by_label(label):
    try:
        # Ottenere l'elenco delle unità logiche
        drives = win32api.GetLogicalDriveStrings().split("\x00")[:-1]
        for drive in drives:
            try:
                # Controlla l'etichetta del volume per ogni unità
                volume_label = win32api.GetVolumeInformation(drive)[0]
                if volume_label == label:
                    return drive  # Restituisce la lettera dell'unità
            except Exception:
                # Ignora unità non accessibili
                continue
        return None  # Se non trova l'etichetta
    except Exception as e:
        return f"Error: {e}"


# Test
drive_letter = get_drive_letter_by_label(USB_LABEL)
if drive_letter:
    apri_dati = drive_letter
else:
    messagebox.showerror("Attenzione", "Pennetta non trovata")
    quit()

# === GC57 Fattorizzazione ===
def gc57_factor(n, c):
    n=n-c
    a = n % c
    b = n - a
    for _ in range(10):
        r = gcd(a, b)
        if r != 1:
            return r, n // r
        a += c
        b -= c
    raise ValueError("Fattorizzazione fallita")


def get_key(p, q, dim_blocco_byte):
    base = hashlib.sha512((str(p ^ q) + str(p + q)).encode()).digest()
    while len(base) < dim_blocco_byte:
        base += hashlib.sha512(base).digest()
    return base[:dim_blocco_byte]


def xor_blocks(data_bytes, key_bytes):
    return bytes([a ^ b for a, b in zip(data_bytes, key_bytes)])


def cifra_dati(data, chiave):
    blocchi = [data[i : i + len(chiave)] for i in range(0, len(data), len(chiave))]
    return b"".join(xor_blocks(blocco, chiave[: len(blocco)]) for blocco in blocchi)


def carica_semiprimo_random(path):
    with open(path, "r") as file:
        righe = file.readlines()
        return int(random.choice(righe).strip())


def salva_file_cifrato(output_path, cifrato, semiprimo, blocco_dim, codice):
    with open(output_path, "wb") as f:
        f.write(b"GC57::")
        f.write(blocco_dim.to_bytes(2, "big"))
        f.write(b"::")
        f.write(codice.encode() + b"::")
        f.write(semiprimo.to_bytes((semiprimo.bit_length() + 7) // 8, "big"))
        f.write(b"::")
        f.write(cifrato)


def carica_file_cifrato(path):
    with open(path, "rb") as f:
        contenuto = f.read()
    if not contenuto.startswith(b"GC57::"):
        raise ValueError("File non valido o corrotto.")
    contenuto = contenuto[6:]
    sep1 = contenuto.index(b"::")
    blocco_dim = int.from_bytes(contenuto[:sep1], "big")
    contenuto = contenuto[sep1 + 2 :]
    sep2 = contenuto.index(b"::")
    codice = contenuto[:sep2].decode()
    contenuto = contenuto[sep2 + 2 :]
    sep3 = contenuto.index(b"::")
    semiprimo = int.from_bytes(contenuto[:sep3], "big")
    cifrato = contenuto[sep3 + 2 :]
    return semiprimo, blocco_dim, cifrato, codice


class principale(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("GC57 QSO Gestione Messaggi Criptati")
        self.geometry("600x520")
        self.config(bg="#5F9EA0")

        introduzione = """Benvenuto nel sistema di cifratura GC57 QSO.\n\nQuesto programma utilizza un sistema crittografico basato su semiprimi di grandi dimensioni, che vengono fattorizzati istantaneamente tramite l'algoritmo GC57.\n\nLa sicurezza si basa sulla combinazione di questi semiprimi con una chiave derivata da una chiavetta USB.\n\nI dati (messaggi e allegati) vengono cifrati con blocchi la cui dimensione dipende dalla grandezza dei fattori primi estratti, rendendo ogni cifratura unica e resistente a qualsiasi attacco, anche ad attacchi quantistici. Per una ulteriore sicurezza strategica\n\ni semiprimi memorizzati all'interno dei file sono offuscati, S=pq+C, in modo da renderli ininfluenti per un attacco di forza bruta in quanto non\nesiste nessun semiprimo ma solo il numero che nasconde il semiprimo"""

        tk.Label(
            self,
            text="Sistema GC57 QSO",
            font=("Helvetica", 25, "bold"),
            bg="#5F9EA0",
            fg="#006400",
        ).pack(pady=10)
        tk.Label(
            self,
            text=introduzione,
            wraplength=560,
            justify="left",
            bg="#5F9EA0",
            font=("Helvetica", 12, "bold"),
        ).pack(padx=20, pady=10)

        px = 200
        py = 420

        tk.Button(
            self,
            text="Invia Messaggio",
            command=self.apri_invia,
            font=("Arial", 12, "bold"),
            bg="#20B2AA",
            fg="white",
        ).place(x=px, y=py, width=200, height=30)
        tk.Button(
            self,
            text="Ricevi Messaggio",
            command=self.apri_ricevi,
            font=("Arial", 12, "bold"),
            bg="#20B2AA",
            fg="white",
        ).place(x=px, y=py + 50, width=200, height=30)

    def apri_invia(self):
        Invia(self).grab_set()

    def apri_ricevi(self):
        Ricevi(self).grab_set()


class Invia(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("GC57 INVIA")
        self.geometry("700x600")
        self.config(bg="#2F4F4F")

        self.testo = tk.Text(
            self,
            width=75,
            height=20,
            bg="#00688B",
            font=("Helvetica", 12),
            wrap=tk.WORD,
        )
        self.testo.place(x=10, y=70)

        self.entry_allegato = tk.Entry(
            self, width=25, font=("Arial", 12, "bold"), bg="#2F4F4F", relief=tk.SUNKEN
        )
        self.entry_allegato.place(x=180, y=495)
        self.entry_codifica = tk.Entry(
            self, width=25, font=("Arial", 12, "bold"), bg="#2F4F4F", relief=tk.SUNKEN
        )
        self.entry_codifica.place(x=180, y=535)

        self.allegato_bytes = None
        self.semiprimo_path = None
        self.chiaveS = None
        self.semiprimo_codice = None

        tk.Label(
            self,
            text="INVIA DATI CRIPTATI",
            bg="#2F4F4F",
            font=("Arial", 18, "bold"),
            fg="#E6E6FA",
        ).place(x=210, y=20)

        tk.Button(
            self,
            text="Invia File",
            fg="#006400",
            font=("Arial", 12, "bold"),
            command=self.codifica,
        ).place(x=500, y=450)
        tk.Button(
            self,
            text="Carica Allegato",
            fg="#006400",
            font=("Arial", 12, "bold"),
            command=self.apri_allegato,
        ).place(x=10, y=490)
        tk.Button(
            self,
            text="Seleziona Codifica",
            fg="#006400",
            font=("Arial", 12, "bold"),
            command=self.apri_codifica,
        ).place(x=10, y=530)

    def apri_allegato(self):
        path = filedialog.askopenfilename(initialdir=DIR_ALLEGATI)
        if path:
            self.entry_allegato.delete(0, tk.END)
            self.entry_allegato.insert(0, path)
            with open(path, "rb") as f:
                self.allegato_bytes = f.read()

    def apri_codifica(self):
        path = filedialog.askopenfilename(initialdir=DIR_SEMIPRIMI)
        if path:
            self.entry_codifica.delete(0, tk.END)
            self.entry_codifica.insert(0, path)
            self.semiprimo_path = path
            semipsel = os.path.basename(path)
            self.semiprimo_codice = semipsel.split(".")[0]
            chiave_path = f"{apri_dati}chiave_{self.semiprimo_codice}"
            if not os.path.exists(chiave_path):
                messagebox.showerror("Errore", f"Chiave USB non trovata: {chiave_path}")
                return
            with open(chiave_path, "r") as f:
                a = int(f.readline())
                # b = int(f.readline())
                # _ = int(f.readline())
                self.chiaveS = a

    def codifica(self):
        if not self.semiprimo_path or not self.chiaveS or not self.semiprimo_codice:
            messagebox.showwarning("Errore", "Prima seleziona la codifica.")
            return
        testo = self.testo.get("1.0", tk.END).strip()
        if not testo:
            messagebox.showerror("Errore", "Inserisci un messaggio di testo prima di procedere.")
            return        
        allegato = self.allegato_bytes
        nome_file = os.path.basename(self.entry_allegato.get()) if allegato else ""
        nome_file_bytes = nome_file.encode()
        semiprimo = carica_semiprimo_random(self.semiprimo_path)
        SP=semiprimo
        p, q = gc57_factor(semiprimo, self.chiaveS)
        blocco_bit = min(p.bit_length(), q.bit_length())
        blocco_byte = blocco_bit // 8
        chiave = get_key(p, q, blocco_byte)
        dati = (
            testo.encode()
            + b"::ALLEGATO::"
            + nome_file_bytes
            + b"::FILE::"
            + (allegato if allegato else b"")
        )
        cifrato = cifra_dati(dati, chiave)
        save_path = filedialog.asksaveasfilename(
            initialdir=DIR_INVIATI, defaultextension=".gcz"
        )
        if save_path:
            salva_file_cifrato(
                save_path, cifrato, SP, blocco_byte, self.semiprimo_codice
            )
            messagebox.showinfo("OK", f"File salvato in:\n{save_path}")


class Ricevi(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("GC57 RICEVI")
        self.geometry("700x550")
        self.config(bg="#292421")

        self.tw1_riceve = tk.Text(
            self,
            width=75,
            height=20,
            bg="#00688B",
            font=("Helvetica", 12),
            wrap=tk.WORD,
        )
        self.tw1_riceve.place(x=10, y=70)

        self.e1_riceve = tk.Entry(
            self,
            width=23,
            font=("Arial", 12, "bold"),
            fg="#66CD00",
            justify="center",
            bg="#292421",
            relief=tk.SUNKEN,
        )
        self.e1_riceve.place(x=450, y=505)

        tk.Label(
            self,
            text="RICEVI DATI CRIPTATI",
            bg="#292421",
            font=("Arial", 18, "bold"),
            fg="#E6E6FA",
        ).place(x=210, y=20)
        tk.Button(
            self,
            text="Carica File",
            fg="#228B22",
            font=("Arial", 12, "bold"),
            command=self.apri_filer,
        ).place(x=10, y=450)
        tk.Label(
            self,
            text="Allegato",
            bg="#292421",
            font=("Arial", 12, "bold"),
            fg="#E6E6FA",
        ).place(x=450, y=475)

    def apri_filer(self):
        path = filedialog.askopenfilename(
            initialdir=DIR_INVIATI, filetypes=[("File GC57", "*.gcz")]
        )
        if not path:
            return
        semiprimo, blocco_byte, cifrato, codice = carica_file_cifrato(path)
        chiave_path = f"{apri_dati}chiave_{codice}"
        if not os.path.exists(chiave_path):
            messagebox.showerror("Errore", f"Chiave USB non trovata: {chiave_path}")
            return
        with open(chiave_path, "r") as f:
            a = int(f.readline())
            # b = int(f.readline())
            # _ = int(f.readline())
            chiaveS = a
        p, q = gc57_factor(semiprimo, chiaveS)
        chiave = get_key(p, q, blocco_byte)
        decifrato = cifra_dati(cifrato, chiave)
        if b"::ALLEGATO::" in decifrato and b"::FILE::" in decifrato:
            testo_parziale, resto = decifrato.split(b"::ALLEGATO::", 1)
            nomefile_bytes, allegato = resto.split(b"::FILE::", 1)
            nomefile = nomefile_bytes.decode(errors="ignore")
            messaggio = testo_parziale
        else:
            messaggio, nomefile, allegato = decifrato, None, None
        self.tw1_riceve.delete("1.0", tk.END)
        self.tw1_riceve.insert(tk.END, messaggio.decode(errors="ignore"))
        if allegato and nomefile:
            salva_path = os.path.join(DIR_RICEVUTI, nomefile)
            with open(salva_path, "wb") as f:
                f.write(allegato)
            self.e1_riceve.delete(0, tk.END)
            self.e1_riceve.insert(0, nomefile)


if __name__ == "__main__":
    principale().mainloop()
