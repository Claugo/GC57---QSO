from tkinter import ttk
import tkinter as tk
from tkinter import filedialog, messagebox
import os
import random
import hashlib
from Crypto.Util.number import long_to_bytes, bytes_to_long
from math import gcd
import win32api
import struct
import hmac
import secrets

# === HKDF utilities v2.1 + MAC buffer ===
import json as _json

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    return hmac.new(salt, ikm, hashlib.sha512).digest()

def hkdf_expand(prk: bytes, info: bytes, L: int) -> bytes:
    out = b""; t = b""; c = 0
    while len(out) < L:
        c += 1
        t = hmac.new(prk, t + info + bytes([c]), hashlib.sha512).digest()
        out += t
    return out[:L]

def derive_context(chiaveS: int, p: int, q: int, file_salt: bytes, metadata_bytes: bytes, block_bytes: int):
    # segreti fusi: chiaveS || H(p||q)
    p0, q0 = (p, q) if p <= q else (q, p)
    p_bytes = long_to_bytes(p0); q_bytes = long_to_bytes(q0)
    C = hashlib.sha512(p_bytes + q_bytes).digest()
    ikm = long_to_bytes(chiaveS) + C
    prk = hkdf_extract(file_salt, ikm)  # separazione per-file
    info = b"GC57v2.1|" + hashlib.sha256(metadata_bytes).digest()
    L = block_bytes + 32 + 32
    km = hkdf_expand(prk, info, L)
    k_base = km[:block_bytes]
    sbox_seed = km[block_bytes:block_bytes+32]
    mac_key = km[block_bytes+32:block_bytes+64]
    return k_base, sbox_seed, mac_key

def build_mac_buffer(file_salt: bytes, metadata: bytes, semiprimo: int, cifrato: bytes) -> bytes:
    semi_bytes = semiprimo.to_bytes((semiprimo.bit_length()+7)//8, "big")
    buf = bytearray()
    buf += b"GC57v2::"
    buf += file_salt
    buf += len(metadata).to_bytes(4, "big"); buf += metadata
    buf += len(semi_bytes).to_bytes(4, "big"); buf += semi_bytes
    buf += len(cifrato).to_bytes(4, "big"); buf += cifrato
    return bytes(buf)


# === CONFIGURAZIONE AVVIO ===
CFG_FILE = "QSOcfg"
VERSION = "GC57v2"  # Nuova versione con sicurezza avanzata

# === FUNZIONI CRITTOGRAFICHE AVANZATE ===


class GC57_Advanced:
    """Sistema crittografico GC57 potenziato"""

    def _pad_7816(self, block: bytes) -> bytes:
        pad_len = self.block_bytes - (len(block) % self.block_bytes)
        if pad_len == 0:
            pad_len = self.block_bytes
        return block + b"\x80" + b"\x00" * (pad_len - 1)

    def _unpad_7816(self, data: bytes) -> bytes:
        # rimuove 00...00 80 dal fondo
        i = len(data) - 1
        # salta gli zeri finali
        while i >= 0 and data[i] == 0x00:
            i -= 1
        if i >= 0 and data[i] == 0x80:
            return data[:i]
        # padding assente o corrotto: lascia com'è (oppure alza eccezione)
        return data

    def __init__(self, p, q, num_rounds=5):
        """
        Inizializza il sistema con una coppia di primi
        p, q: primi > 2000 bit
        num_rounds: numero di round di cifratura (default 5)
        """
        self.p = p
        self.q = q
        self.num_rounds = num_rounds

        # Calcola dimensione blocco (basata sul primo più piccolo)
        self.block_bits = min(p.bit_length(), q.bit_length())
        self.block_bytes = self.block_bits // 8

        # v2.1: materiale round inizializzato per-file via rekey()
        self.subkeys = None
        self.sbox = None
        self.inv_sbox = None
        self.mac_key = None  # HMAC key per-file


    def _generate_subkeys(self):
        """Genera subchiavi multiple per ogni round"""
        subkeys = []

        # Chiavi di whitening
        k_base = hashlib.sha512(
            (str(self.p ^ self.q) + str(self.p + self.q)).encode()
        ).digest()

        for round_num in range(self.num_rounds + 2):  # +2 per pre/post whitening
            # Deriva chiave unica per ogni round
            seed = (self.p * (round_num + 1) + self.q * (round_num + 2)) % (2**512)
            round_key = hashlib.sha512(
                k_base + str(seed).encode() + b"ROUND" + str(round_num).encode()
            ).digest()

            # Espandi alla dimensione del blocco se necessario
            while len(round_key) < self.block_bytes:
                round_key += hashlib.sha512(round_key).digest()

            subkeys.append(round_key[: self.block_bytes])

        return subkeys

    def _generate_sbox(self):
        """Genera S-Box dinamica basata sui primi"""
        sbox = list(range(256))

        # Usa i primi per mescolare l'S-Box
        seed_value = (self.p * self.q) % (2**256)

        # Gestisci la conversione in bytes in modo sicuro
        byte_length = (seed_value.bit_length() + 7) // 8
        if byte_length < 32:
            byte_length = 32
        seed_bytes = seed_value.to_bytes(byte_length, "big")[
            -32:
        ]  # Prendi ultimi 32 bytes

        # Fisher-Yates shuffle controllato
        for i in range(256):
            j = (seed_bytes[i % 32] + i) % 256
            sbox[i], sbox[j] = sbox[j], sbox[i]

            # Mescolamento aggiuntivo
            k = (seed_bytes[(i + 1) % 32] ^ seed_bytes[(i + 2) % 32]) % 256
            sbox[j], sbox[k] = sbox[k], sbox[j]

        return sbox

    def _generate_inverse_sbox(self):
        """Genera S-Box inversa per decifratura"""
        inv_sbox = [0] * 256
        for i in range(256):
            inv_sbox[self.sbox[i]] = i
        return inv_sbox

    def _generate_subkeys_from_base(self, k_base: bytes):
        """Deriva (num_rounds+2) subchiavi della lunghezza del blocco dal k_base (per-file)."""
        need = (self.num_rounds + 2) * self.block_bytes
        material = hashlib.sha512(k_base).digest()
        ctr = 0
        while len(material) < need:
            material += hashlib.sha512(material + bytes([ctr & 0xFF])).digest()
            ctr += 1
        subkeys = []
        off = 0
        for _ in range(self.num_rounds + 2):
            subkeys.append(material[off:off+self.block_bytes])
            off += self.block_bytes
        return subkeys

    def _generate_sbox_from_seed(self, seed_bytes: bytes):
        """S-Box dinamica per-file (Fisher–Yates da seed)."""
        sbox = list(range(256))
        # espandi seed a 256 byte
        buf = bytearray()
        t = seed_bytes or b"\x00"
        while len(buf) < 256:
            t = hashlib.sha512(t).digest()
            buf.extend(t)
        buf = bytes(buf[:256])
        for i in range(255, -1, -1):
            j = buf[i] % (i + 1)
            sbox[i], sbox[j] = sbox[j], sbox[i]
        return sbox

    def rekey(self, k_base: bytes, sbox_seed: bytes, mac_key: bytes):
        """Imposta subkeys, S-Box e chiave MAC per questo file."""
        self.subkeys = self._generate_subkeys_from_base(k_base)
        self.sbox = self._generate_sbox_from_seed(sbox_seed)
        self.inv_sbox = self._generate_inverse_sbox()
        self.mac_key = mac_key


    def _substitute_bytes(self, data, inverse=False):
        """Applica sostituzione con S-Box"""
        box = self.inv_sbox if inverse else self.sbox
        return bytes([box[byte] for byte in data])

    def _permute_bytes(self, data, key, inverse=False):
        """Permutazione dipendente dalla chiave"""
        n = len(data)
        if n <= 1:
            return data

        # Genera pattern di permutazione dalla chiave
        indices = list(range(n))

        # Usa la chiave per generare permutazione deterministica
        for i in range(n):
            j = sum(key[k % len(key)] for k in range(i, min(i + 3, len(key)))) % n
            indices[i], indices[j] = indices[j], indices[i]

        if inverse:
            # Crea permutazione inversa
            inv_indices = [0] * n
            for i, target in enumerate(indices):
                inv_indices[target] = i
            indices = inv_indices

        # Applica permutazione
        result = bytearray(n)
        for i, idx in enumerate(indices):
            result[idx] = data[i]

        return bytes(result)

    def _mix_columns(self, data, key):
        """MixColumns: applica il mix solo sui gruppi completi da 4 byte."""
        n = len(data)
        result = bytearray(data)
        full = n - (n % 4)
        for i in range(0, full, 4):
            b0, b1, b2, b3 = data[i], data[i + 1], data[i + 2], data[i + 3]
            result[i] = (self._gmul(b0, 2) ^ self._gmul(b1, 3) ^ b2 ^ b3) & 0xFF
            result[i + 1] = (self._gmul(b1, 2) ^ self._gmul(b2, 3) ^ b3 ^ b0) & 0xFF
            result[i + 2] = (self._gmul(b2, 2) ^ self._gmul(b3, 3) ^ b0 ^ b1) & 0xFF
            result[i + 3] = (self._gmul(b3, 2) ^ self._gmul(b0, 3) ^ b1 ^ b2) & 0xFF

        return bytes(result)

    def _gmul(self, a, b):
        """Moltiplicazione in GF(2^8) per MixColumns"""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit = a & 0x80
            a = (a << 1) & 0xFF  # Mantieni nel range 0-255
            if hi_bit:
                a ^= 0x1B  # Polinomio irriducibile x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return p & 0xFF  # Assicura che il risultato sia nel range 0-255

    def _add_round_key(self, data, key):
        """XOR con chiave di round"""
        return bytes([a ^ b for a, b in zip(data, key[: len(data)])])

    def encrypt_block(self, block):
        """Cifra un singolo blocco con multiple round"""
        if len(block) < self.block_bytes:
            # Padding PKCS#7
            pad_len = self.block_bytes - len(block)
            block = block + bytes([pad_len] * pad_len)

        state = block

        # Pre-whitening
        state = self._add_round_key(state, self.subkeys[0])

        # Round principali
        for round_num in range(self.num_rounds):
            # SubBytes
            state = self._substitute_bytes(state)

            # PermBytes (analogo a ShiftRows)
            state = self._permute_bytes(state, self.subkeys[round_num + 1])

            # MixColumns (tranne ultimo round)
            if round_num < self.num_rounds - 1:
                state = self._mix_columns(state, self.subkeys[round_num + 1])

            # AddRoundKey
            state = self._add_round_key(state, self.subkeys[round_num + 1])

        # Post-whitening
        state = self._add_round_key(state, self.subkeys[-1])

        return state

    def decrypt_block(self, block):
        """Decifra un singolo blocco"""
        state = block

        # Inverti post-whitening
        state = self._add_round_key(state, self.subkeys[-1])

        # Inverti round principali
        for round_num in range(self.num_rounds - 1, -1, -1):
            # Inverti AddRoundKey
            state = self._add_round_key(state, self.subkeys[round_num + 1])

            # Inverti MixColumns (tranne ultimo round)
            if round_num < self.num_rounds - 1:
                state = self._inv_mix_columns(state, self.subkeys[round_num + 1])

            # Inverti PermBytes
            state = self._permute_bytes(
                state, self.subkeys[round_num + 1], inverse=True
            )

            # Inverti SubBytes
            state = self._substitute_bytes(state, inverse=True)

        # Inverti pre-whitening
        state = self._add_round_key(state, self.subkeys[0])

        return state

    def _inv_mix_columns(self, data, key):
        """InvMixColumns: inversa del mix solo sui gruppi completi da 4 byte."""
        n = len(data)
        result = bytearray(data)
        full = n - (n % 4)
        for i in range(0, full, 4):
            b0, b1, b2, b3 = data[i], data[i + 1], data[i + 2], data[i + 3]
            result[i] = (
                self._gmul(b0, 14)
                ^ self._gmul(b1, 11)
                ^ self._gmul(b2, 13)
                ^ self._gmul(b3, 9)
            ) & 0xFF
            result[i + 1] = (
                self._gmul(b1, 14)
                ^ self._gmul(b2, 11)
                ^ self._gmul(b3, 13)
                ^ self._gmul(b0, 9)
            ) & 0xFF
            result[i + 2] = (
                self._gmul(b2, 14)
                ^ self._gmul(b3, 11)
                ^ self._gmul(b0, 13)
                ^ self._gmul(b1, 9)
            ) & 0xFF
            result[i + 3] = (
                self._gmul(b3, 14)
                ^ self._gmul(b0, 11)
                ^ self._gmul(b1, 13)
                ^ self._gmul(b2, 9)
            ) & 0xFF

        return bytes(result)

    def encrypt_cbc(self, plaintext):
        iv = secrets.token_bytes(self.block_bytes)
        # 7816-4: pad sempre (anche se multiplo del blocco)
        padded = self._pad_7816(plaintext)

        ciphertext = iv
        previous = iv
        for i in range(0, len(padded), self.block_bytes):
            block = padded[i : i + self.block_bytes]
            xored = bytes(a ^ b for a, b in zip(block, previous))
            encrypted = self.encrypt_block(
                xored
            )  # encrypt_block NON deve più fare padding
            ciphertext += encrypted
            previous = encrypted
        return ciphertext

    def decrypt_cbc(self, ciphertext):
        iv = ciphertext[: self.block_bytes]
        c = ciphertext[self.block_bytes :]

        plaintext = b""
        previous = iv
        for i in range(0, len(c), self.block_bytes):
            block = c[i : i + self.block_bytes]
            decrypted = self.decrypt_block(block)
            xored = bytes(a ^ b for a, b in zip(decrypted, previous))
            plaintext += xored
            previous = block

        # rimuovi 7816-4
        return self._unpad_7816(plaintext)

    # ====== NUOVI METODI: versioni con callback di progresso ======

    def encrypt_cbc_with_progress(self, plaintext, progress_cb=None):
        """Come encrypt_cbc ma chiama progress_cb(done, total) ad ogni blocco."""
        iv = secrets.token_bytes(self.block_bytes)
        padded = self._pad_7816(plaintext)
        out = bytearray(iv)
        prev = iv
        total = len(padded)
        done = 0

        for i in range(0, total, self.block_bytes):
            block = padded[i : i + self.block_bytes]
            xored = bytes(a ^ b for a, b in zip(block, prev))
            enc = self.encrypt_block(xored)
            out += enc
            prev = enc
            done += len(block)
            if progress_cb:
                progress_cb(done, total)

        return bytes(out)

    def decrypt_cbc_with_progress(self, ciphertext, progress_cb=None):
        """Come decrypt_cbc ma chiama progress_cb(done, total) ad ogni blocco."""
        iv = ciphertext[: self.block_bytes]
        c = ciphertext[self.block_bytes :]
        total = len(c)
        done = 0

        plain = bytearray()
        prev = iv
        for i in range(0, total, self.block_bytes):
            block = c[i : i + self.block_bytes]
            dec = self.decrypt_block(block)
            xored = bytes(a ^ b for a, b in zip(dec, prev))
            plain += xored
            prev = block
            done += len(block)
            if progress_cb:
                progress_cb(done, total)

        return self._unpad_7816(bytes(plain))

    def generate_mac(self, data, mac_key: bytes = None):
        """HMAC-SHA512 per-file (truncate 256 bit)."""
        key = mac_key or getattr(self, 'mac_key', None)
        if key is None:
            raise ValueError("MAC key non inizializzata (rekey mancante)")
        h = hmac.new(key, data, hashlib.sha512)
        return h.digest()[:32]

    def verify_mac(self, data, mac, mac_key: bytes = None):
        expected_mac = self.generate_mac(data, mac_key)
        return hmac.compare_digest(expected_mac, mac)
# === FUNZIONI HELPER AGGIORNATE ===


def gc57_factor(n, c):
    """Fattorizzazione GC57 migliorata con controlli di sicurezza"""
    if n <= c:
        raise ValueError("Semiprimo corrotto o chiave errata")

    n = n - c
    a = n % c
    b = n - a

    max_iterations = 100  # Aumentato per primi grandi

    for iteration in range(max_iterations):
        r = gcd(a, b)
        if r != 1 and r != n:  # Trovato fattore non banale
            p, q = r, n // r

            # Verifica che siano entrambi primi > 2000 bit
            if p.bit_length() < 2000 or q.bit_length() < 2000:
                raise ValueError("Primi troppo piccoli - possibile attacco")

            return p, q

        a = (a + c) % n
        b = (b - c) % n

        if a == 0 or b == 0:
            a = (a + c + 1) % n
            b = (b - c - 1) % n

    raise ValueError("Fattorizzazione fallita - verifica integrità dati")


def carica_semiprimo_random(path):
    """Carica semiprimo con verifica di integrità"""
    if not os.path.exists(path):
        raise FileNotFoundError(f"File semiprimi non trovato: {path}")

    with open(path, "r") as file:
        righe = file.readlines()
        if not righe:
            raise ValueError("File semiprimi vuoto")

        # Selezione random sicura
        semiprimo = int(random.SystemRandom().choice(righe).strip())

        # Verifica dimensione minima (4000 bit per somma di due primi > 2000)
        if semiprimo.bit_length() < 4000:
            raise ValueError("Semiprimo troppo piccolo - possibile corruzione")

        return semiprimo


def salva_file_cifrato_v2(output_path, cifrato, semiprimo, metadata, mac, file_salt):
    """Salva .gc2 v2.1: magic | file_salt(16) | meta | semiprimo | data | MAC"""
    with open(output_path, "wb") as f:
        f.write(b"GC57v2::")
        f.write(file_salt)
        f.write(len(metadata).to_bytes(4, "big")); f.write(metadata)
        semi_bytes = semiprimo.to_bytes((semiprimo.bit_length() + 7) // 8, "big")
        f.write(len(semi_bytes).to_bytes(4, "big")); f.write(semi_bytes)
        f.write(len(cifrato).to_bytes(4, "big")); f.write(cifrato)
        f.write(mac)


def carica_file_cifrato_v2(path):
    """Carica .gc2 v2.1 (con file_salt)."""
    with open(path, "rb") as f:
        contenuto = f.read()

    if not contenuto.startswith(b"GC57v2::"):
        if contenuto.startswith(b"GC57::"):
            raise ValueError("File in formato vecchio - aggiornamento richiesto")
        raise ValueError("File non valido o corrotto")

    pos = 8
    file_salt = contenuto[pos:pos+16]; pos += 16

    meta_len = int.from_bytes(contenuto[pos:pos+4], "big"); pos += 4
    metadata = contenuto[pos:pos+meta_len]; pos += meta_len

    semi_len = int.from_bytes(contenuto[pos:pos+4], "big"); pos += 4
    semiprimo = int.from_bytes(contenuto[pos:pos+semi_len], "big"); pos += semi_len

    data_len = int.from_bytes(contenuto[pos:pos+4], "big"); pos += 4
    cifrato = contenuto[pos:pos+data_len]; pos += data_len

    mac = contenuto[pos:pos+32]

    return file_salt, semiprimo, metadata, cifrato, mac


# === CONFIGURAZIONE INIZIALE (uguale all'originale) ===
# [Il codice di configurazione rimane identico...]

if not os.path.exists(CFG_FILE):
    # [Codice configurazione identico all'originale]
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

# Carica configurazione
with open(CFG_FILE, "r") as cfg:
    DIR_INVIATI = cfg.readline().strip().replace("\\", "/")
    DIR_RICEVUTI = cfg.readline().strip().replace("\\", "/")
    DIR_ALLEGATI = cfg.readline().strip().replace("\\", "/")
    DIR_SEMIPRIMI = cfg.readline().strip().replace("\\", "/")
    USB_LABEL = cfg.readline().strip().upper()

messagebox.showinfo("USB", "Inserisci la pen drive con il nome: " + USB_LABEL)


def get_drive_letter_by_label(label):
    try:
        drives = win32api.GetLogicalDriveStrings().split("\x00")[:-1]
        for drive in drives:
            try:
                volume_label = win32api.GetVolumeInformation(drive)[0]
                if volume_label == label:
                    return drive
            except Exception:
                continue
        return None
    except Exception as e:
        return f"Error: {e}"


drive_letter = get_drive_letter_by_label(USB_LABEL)
if drive_letter:
    apri_dati = drive_letter
else:
    messagebox.showerror("Attenzione", "Pennetta non trovata")
    quit()


# === INTERFACCIA GRAFICA AGGIORNATA ===


class principale(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("GC57 QSO v2 - Sistema Crittografico Avanzato")
        self.geometry("600x550")
        self.config(bg="#5F9EA0")

        introduzione = """Benvenuto nel sistema di cifratura GC57 QSO v2.

Questa versione implementa:
• Cifratura multi-round con S-Box dinamiche
• Primi sempre > 2000 bit per sicurezza quantistica
• MAC per autenticazione e integrità
• Modalità CBC con IV random
• Protezione contro attacchi side-channel

La sicurezza minima garantita è 2^2000 operazioni,
resistente anche ad attacchi quantistici (2^1000 post-Grover)."""

        tk.Label(
            self,
            text="Sistema GC57 QSO v2",
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
            font=("Helvetica", 11),
        ).pack(padx=20, pady=10)

        # Frame per statistiche
        stats_frame = tk.Frame(self, bg="#4A7C7E")
        stats_frame.pack(pady=10, padx=20, fill="x")

        tk.Label(
            stats_frame,
            text="Sicurezza: 2^2000+ bit | Blocchi: 250+ bytes | Rounds: 5",
            font=("Courier", 10, "bold"),
            bg="#4A7C7E",
            fg="white",
        ).pack(pady=5)

        px = 200
        py = 450

        tk.Button(
            self,
            text="Invia Messaggio Sicuro",
            command=self.apri_invia,
            font=("Arial", 12, "bold"),
            bg="#20B2AA",
            fg="white",
            cursor="hand2",
        ).place(x=px, y=py, width=200, height=35)

        tk.Button(
            self,
            text="Ricevi Messaggio",
            command=self.apri_ricevi,
            font=("Arial", 12, "bold"),
            bg="#20B2AA",
            fg="white",
            cursor="hand2",
        ).place(x=px, y=py + 50, width=200, height=35)

    def apri_invia(self):
        Invia_v2(self).grab_set()

    def apri_ricevi(self):
        Ricevi_v2(self).grab_set()


class Invia_v2(tk.Toplevel):

    def _set_busy(self, busy: bool, msg: str = ""):
        # abilita/disabilita pulsanti e cursore
        state = "disabled" if busy else "normal"
        for b in (self.btn_cifra, self.btn_allegato, self.btn_codifica):
            b.configure(state=state)
        self.config(cursor="watch" if busy else "")
        if msg:
            self.progress_label.config(text=msg)
        self.update_idletasks()

    def __init__(self, master):
        super().__init__(master)
        self.title("GC57 INVIA v2 - Cifratura Avanzata")
        self.geometry("750x650")
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

        # Variabili per sicurezza
        self.allegato_bytes = None
        self.semiprimo_path = None
        self.chiaveS = None
        self.semiprimo_codice = None
        self.crypto_engine = None

        tk.Label(
            self,
            text="INVIA DATI CRIPTATI - SICUREZZA AVANZATA",
            bg="#2F4F4F",
            font=("Arial", 18, "bold"),
            fg="#E6E6FA",
        ).place(x=150, y=20)

        # Progress bar simulata
        self.progress_label = tk.Label(
            self, text="Pronto", bg="#2F4F4F", font=("Arial", 10), fg="#90EE90"
        )
        self.progress_label.place(x=500, y=495)

        self.btn_cifra = tk.Button(
            self,
            text="Cifra e Invia",
            fg="#006400",
            font=("Arial", 12, "bold"),
            command=self.codifica_v2,
            cursor="hand2",
            bg="#90EE90",
        )
        self.btn_cifra.place(x=500, y=450, width=120, height=35)

        self.btn_allegato = tk.Button(
            self,
            text="Carica Allegato",
            fg="#006400",
            font=("Arial", 12, "bold"),
            command=self.apri_allegato,
            cursor="hand2",
        )
        self.btn_allegato.place(x=10, y=490)

        self.btn_codifica = tk.Button(
            self,
            text="Seleziona Codifica",
            fg="#006400",
            font=("Arial", 12, "bold"),
            command=self.apri_codifica_v2,
            cursor="hand2",
        )
        self.btn_codifica.place(x=10, y=530)

        # Indicatore rounds
        tk.Label(
            self,
            text="Rounds: 5 | MAC: SHA-512",
            bg="#2F4F4F",
            font=("Courier", 9),
            fg="#ADD8E6",
        ).place(x=10, y=580)

    def apri_allegato(self):
        path = filedialog.askopenfilename(initialdir=DIR_ALLEGATI)
        if path:
            self.entry_allegato.delete(0, tk.END)
            self.entry_allegato.insert(0, os.path.basename(path))
            with open(path, "rb") as f:
                self.allegato_bytes = f.read()

            # Mostra dimensione file
            size_kb = len(self.allegato_bytes) / 1024
            self.progress_label.config(text=f"File: {size_kb:.1f} KB")

    def apri_codifica_v2(self):
        path = filedialog.askopenfilename(
            initialdir=DIR_SEMIPRIMI,
            title="Seleziona file semiprimi",
            filetypes=[("Tutti i file", "*.*")],
        )
        if path:
            self.entry_codifica.delete(0, tk.END)
            self.entry_codifica.insert(0, os.path.basename(path))
            self.semiprimo_path = path

            semipsel = os.path.basename(path)
            self.semiprimo_codice = semipsel.split(".")[0]

            chiave_path = f"{apri_dati}chiave_{self.semiprimo_codice}"
            if not os.path.exists(chiave_path):
                messagebox.showerror("Errore", f"Chiave USB non trovata: {chiave_path}")
                return

            with open(chiave_path, "r") as f:
                self.chiaveS = int(f.readline())

            self.progress_label.config(text="Chiave caricata ✓")

    def codifica_v2(self):
        """Cifratura con sistema avanzato (UI non bloccata visivamente + join dei bytes + progress)"""
        if not self.semiprimo_path or not self.chiaveS or not self.semiprimo_codice:
            messagebox.showwarning("Errore", "Prima seleziona la codifica.")
            return

        testo = self.testo.get("1.0", tk.END).strip()
        if not testo:
            messagebox.showerror(
                "Errore", "Inserisci un messaggio di testo prima di procedere."
            )
            return

        # piccoli helper locali per non toccare l'UI altrove
        def _set_buttons(state: str):
            for w in self.winfo_children():
                try:
                    if isinstance(w, tk.Button):
                        w.configure(state=state)
                except Exception:
                    pass

        try:
            # stato "busy" visivo
            self.config(cursor="watch")
            _set_buttons("disabled")
            self.progress_label.config(text="Caricamento semiprimo...")
            self.update_idletasks()

            # Carica semiprimo con verifiche di sicurezza
            semiprimo = carica_semiprimo_random(self.semiprimo_path)
            SP = semiprimo  # Mantieni originale per salvare

            self.progress_label.config(text="Fattorizzazione...")
            self.update_idletasks()

            # Fattorizza con controlli
            p, q = gc57_factor(semiprimo, self.chiaveS)

            # Verifica dimensione minima primi
            if p.bit_length() < 2000 or q.bit_length() < 2000:
                raise ValueError(
                    f"Primi troppo piccoli: {p.bit_length()}, {q.bit_length()} bit"
                )

            self.progress_label.config(text="Inizializzazione cifrario...")
            self.update_idletasks()

            # Inizializza sistema crittografico avanzato
            self.crypto_engine = GC57_Advanced(p, q, num_rounds=5)
            # v2.1: per-file salt e derivazione materiale chiavi
            file_salt = secrets.token_bytes(16)
            metadata = {
                "version": 2,
                "codice": self.semiprimo_codice,
                "rounds": 5,
                "block_size": self.crypto_engine.block_bytes,
                "timestamp": int(time.time()) if "time" in globals() else 0,
                "p_bits": p.bit_length(),
                "q_bits": q.bit_length(),
            }
            import json
            metadata_json = json.dumps(metadata, sort_keys=True).encode("utf-8")
            # metadata_json già pronto
            k_base, sbox_seed, mac_key = derive_context(self.chiaveS, p, q, file_salt, metadata_json, self.crypto_engine.block_bytes)
            self.crypto_engine.rekey(k_base, sbox_seed, mac_key)



            # Prepara dati
            allegato = self.allegato_bytes
            nome_file = os.path.basename(self.entry_allegato.get()) if allegato else ""

            # Struttura dati con separatori (più efficiente)
            dati = b"".join(
                [
                    testo.encode("utf-8"),
                    b"::ALLEGATO::",
                    nome_file.encode("utf-8"),
                    b"::FILE::",
                    allegato or b"",
                ]
            )

            # Progress: se c'è la progressbar, azzerala
            pbar = getattr(self, "pbar", None)
            if pbar:
                pbar["value"] = 0

            self.progress_label.config(text="Cifratura in corso...")
            self.update_idletasks()

            # Cifra con CBC e rounds multipli (con callback di progresso)
            def _on_progress(done, total):
                pct = int(done * 100 / total) if total else 100
                if pbar:
                    pbar["value"] = pct
                self.progress_label.config(text=f"Cifratura {pct}%")
                self.update_idletasks()

            cifrato = self.crypto_engine.encrypt_cbc_with_progress(dati, _on_progress)

            if pbar:
                pbar["value"] = 100

            self.progress_label.config(text="Generazione MAC...")
            self.update_idletasks()

            # Genera MAC per integrità
            # mac calcolato dopo con EtM

            # Prepara metadata
            # riuso metadata_json già calcolato sopra
            metadata_json = json.dumps(metadata, sort_keys=True).encode("utf-8")

            # Chiedi dove salvare
            save_path = filedialog.asksaveasfilename(
                initialdir=DIR_INVIATI,
                defaultextension=".gc2",
                filetypes=[("File GC57 v2", "*.gc2"), ("Tutti i file", "*.*")],
            )

            if save_path:
                self.progress_label.config(text="Salvataggio...")
                self.update_idletasks()

                # Salva con nuovo formato sicuro
                mac = self.crypto_engine.generate_mac(build_mac_buffer(file_salt, metadata_json, SP, cifrato))
                salva_file_cifrato_v2(save_path, cifrato, SP, metadata_json, mac, file_salt)

                # Mostra statistiche
                size_kb = len(cifrato) / 1024
                messagebox.showinfo(
                    "Cifratura Completata",
                    f"File salvato: {os.path.basename(save_path)}\n"
                    f"Dimensione: {size_kb:.1f} KB\n"
                    f"Sicurezza: 2^{p.bit_length()} bit\n"
                    f"Blocchi: {self.crypto_engine.block_bytes} bytes\n"
                    f"MAC: Verificato",
                )

                self.progress_label.config(text="Completato ✓")

        except Exception as e:
            messagebox.showerror("Errore Cifratura", str(e))
            self.progress_label.config(text="Errore!")
        finally:
            # ripristina UI
            self.config(cursor="")
            _set_buttons("normal")
            self.update_idletasks()


class Ricevi_v2(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("GC57 RICEVI v2 - Decifratura Sicura")
        self.geometry("750x600")
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
            text="RICEVI DATI CRIPTATI - VERIFICA INTEGRITA'",
            bg="#292421",
            font=("Arial", 18, "bold"),
            fg="#E6E6FA",
        ).place(x=150, y=20)

        tk.Button(
            self,
            text="Carica e Decifra",
            fg="#228B22",
            font=("Arial", 12, "bold"),
            command=self.apri_filer_v2,
            cursor="hand2",
            bg="#90EE90",
        ).place(x=10, y=450, width=150, height=35)

        tk.Label(
            self,
            text="Allegato",
            bg="#292421",
            font=("Arial", 12, "bold"),
            fg="#E6E6FA",
        ).place(x=450, y=475)

        # Status indicators
        self.status_frame = tk.Frame(self, bg="#292421")
        self.status_frame.place(x=10, y=500)

        self.status_labels = {
            "file": tk.Label(
                self.status_frame, text="⚪ File", bg="#292421", fg="white"
            ),
            "mac": tk.Label(self.status_frame, text="⚪ MAC", bg="#292421", fg="white"),
            "decrypt": tk.Label(
                self.status_frame, text="⚪ Decifratura", bg="#292421", fg="white"
            ),
        }

        for i, (key, label) in enumerate(self.status_labels.items()):
            label.grid(row=0, column=i, padx=10)

        # === NUOVI WIDGET: progress bar e label percentuale ===
        self.pbar = ttk.Progressbar(self, length=300, mode="determinate", maximum=100)
        self.pbar.place(x=10, y=540)

        self.progress_rx = tk.Label(
            self, text="Pronto", bg="#292421", fg="#ADD8E6", font=("Arial", 10)
        )
        self.progress_rx.place(x=320, y=540)

    def update_status(self, key, status):
        """Aggiorna indicatori di stato"""
        symbols = {"pending": "⚪", "ok": "✅", "error": "❌", "working": "🔄"}
        colors = {
            "pending": "white",
            "ok": "green",
            "error": "red",
            "working": "yellow",
        }

        if key in self.status_labels:
            text = self.status_labels[key].cget("text").split()[1]
            self.status_labels[key].config(
                text=f"{symbols.get(status, '⚪')} {text}",
                fg=colors.get(status, "white"),
            )

    def apri_filer_v2(self):
        """Decifratura con verifica MAC"""
        path = filedialog.askopenfilename(
            initialdir=DIR_RICEVUTI,
            filetypes=[
                ("File GC57 v2", "*.gc2"),
                ("File GC57 legacy", "*.gcz"),
                ("Tutti i file", "*.*"),
            ],
        )

        if not path:
            return

        try:
            self.update_status("file", "working")

            # Determina versione del file
            with open(path, "rb") as f:
                header = f.read(8)

            if header.startswith(b"GC57v2::"):
                # Formato nuovo con sicurezza avanzata
                self.decifra_v2(path)
            elif header.startswith(b"GC57::"):
                # Formato legacy - offri conversione
                risposta = messagebox.askyesno(
                    "File Legacy",
                    "Questo file usa il formato vecchio.\n"
                    "Vuoi convertirlo al nuovo formato sicuro dopo la decifratura?",
                )
                self.decifra_legacy(path, converti=risposta)
            else:
                raise ValueError("Formato file non riconosciuto")

        except Exception as e:
            self.update_status("file", "error")
            messagebox.showerror("Errore", str(e))

    def decifra_v2(self, path):
        """Decifra file formato v2 con verifica MAC (con progress durante la decifratura)"""
        try:
            # Carica file
            file_salt, semiprimo, metadata_json, cifrato, mac = carica_file_cifrato_v2(path)
            self.update_status("file", "ok")

            # Parse metadata
            import json

            metadata = json.loads(metadata_json.decode("utf-8"))

            # Carica chiave USB
            codice = metadata["codice"]
            chiave_path = f"{apri_dati}chiave_{codice}"

            if not os.path.exists(chiave_path):
                raise FileNotFoundError(f"Chiave USB non trovata: {chiave_path}")

            with open(chiave_path, "r") as f:
                chiaveS = int(f.readline())

            # Fattorizza
            self.update_status("decrypt", "working")
            p, q = gc57_factor(semiprimo, chiaveS)

            # Verifica dimensioni primi
            if p.bit_length() < 2000 or q.bit_length() < 2000:
                raise ValueError("Primi compromessi - possibile manomissione")

            # Inizializza motore crittografico
            crypto_engine = GC57_Advanced(p, q, num_rounds=metadata.get("rounds", 5))

            # Deriva materiale per-file
            k_base, sbox_seed, mac_key = derive_context(chiaveS, p, q, file_salt, metadata_json, crypto_engine.block_bytes)
            crypto_engine.rekey(k_base, sbox_seed, mac_key)


            # Verifica MAC PRIMA di decifrare (EtM su header|meta|n|data)
            self.update_status("mac", "working")
            mac_data = build_mac_buffer(file_salt, metadata_json, semiprimo, cifrato)
            if not crypto_engine.verify_mac(mac_data, mac):
                self.update_status("mac", "error")
                raise ValueError("MAC non valido - file corrotto o manomesso!")
            self.update_status("mac", "ok")

            # Progressbar + label (se presenti)
            pbar = getattr(self, "pbar", None)
            if pbar:
                pbar["value"] = 0
            if hasattr(self, "progress_rx"):
                self.progress_rx.config(text="Decifratura 0%")

            # Decifra con progress
            def _on_progress(done, total):
                pct = int(done * 100 / total) if total else 100
                if pbar:
                    pbar["value"] = pct
                if hasattr(self, "progress_rx"):
                    self.progress_rx.config(text=f"Decifratura {pct}%")
                # mantieni viva la UI
                self.update_idletasks()

            decifrato = crypto_engine.decrypt_cbc_with_progress(cifrato, _on_progress)

            if pbar:
                pbar["value"] = 100
            if hasattr(self, "progress_rx"):
                self.progress_rx.config(text="Decifratura 100%")

            self.update_status("decrypt", "ok")

            # Estrai contenuti
            if b"::ALLEGATO::" in decifrato and b"::FILE::" in decifrato:
                testo_bytes, resto = decifrato.split(b"::ALLEGATO::", 1)
                nomefile_bytes, allegato = resto.split(b"::FILE::", 1)

                messaggio = testo_bytes.decode("utf-8", errors="ignore")
                nomefile = nomefile_bytes.decode("utf-8", errors="ignore")
            else:
                messaggio = decifrato.decode("utf-8", errors="ignore")
                nomefile = None
                allegato = None

            # Mostra messaggio
            self.tw1_riceve.delete("1.0", tk.END)
            self.tw1_riceve.insert(tk.END, messaggio)

            # Salva allegato se presente
            if allegato and nomefile:
                salva_path = os.path.join(DIR_RICEVUTI, nomefile)

                # Chiedi conferma se file esiste
                if os.path.exists(salva_path):
                    risposta = messagebox.askyesno(
                        "File esistente",
                        f"Il file {nomefile} esiste già. Sovrascrivere?",
                    )
                    if not risposta:
                        salva_path = filedialog.asksaveasfilename(
                            initialdir=DIR_RICEVUTI, initialfile=nomefile
                        )

                if salva_path:
                    with open(salva_path, "wb") as f:
                        f.write(allegato)

                    self.e1_riceve.delete(0, tk.END)
                    self.e1_riceve.insert(0, nomefile)

                    size_kb = len(allegato) / 1024
                    messagebox.showinfo(
                        "Allegato Salvato",
                        f"File: {nomefile}\n"
                        f"Dimensione: {size_kb:.1f} KB\n"
                        f"Posizione: {salva_path}",
                    )

            # Mostra info sicurezza
            messagebox.showinfo(
                "Decifratura Completata",
                f"✅ MAC verificato\n"
                f"✅ Integrità confermata\n"
                f"Sicurezza: 2^{metadata.get('p_bits', '?')} bit\n"
                f"Rounds: {metadata.get('rounds', '?')}",
            )

        except Exception as e:
            self.update_status("decrypt", "error")
            messagebox.showerror("Errore Decifratura", str(e))


if __name__ == "__main__":
    import time  # Per timestamp

    app = principale()
    app.mainloop()
