# Crea database semiprimi con due fattori primi - agosto 2024
# inserito il riconoscimento nome pendrive
import tkinter as tk
from PIL import Image, ImageTk
import os
from tkinter import simpledialog
from tkinter import filedialog
from tkinter import messagebox
from random import randint, seed
import time
from gmpy2 import next_prime as nextprime
from math import log, gcd
import win32api

T = int(time.time())
seed(T)

messagebox.showinfo("USB","Inserisci la pen drive QSO")

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
volume_label = "QSO"  # Inserisci il nome della tua pennetta
drive_letter = get_drive_letter_by_label(volume_label)
if drive_letter:
    apri_dati=drive_letter
else:
    messagebox.showerror("Attenzione","Pennetta non trovata")
    quit()


cartella3='c:\\db_qso' #*cartella semiprimi

if os.path.exists(cartella3):
    pass
else:
    os.makedirs(cartella3)


# **********************************************************
# *                verifica dimensione
# **********************************************************
def verifica():
    nds = e1.get()
    nds2 = e11.get()
    ep = e3.get()
    eq = e4.get()

    # Verifica che nessun campo sia vuoto
    if any(field == "" for field in [nds, nds2, ep, eq]):
        messagebox.showerror(
            "Attenzione:", "p1, q1, ec, ep, eq devono essere compilati"
        )
        return

    # Verifica che tutti i campi contengano solo numeri interi positivi
    if not all(field.isdigit() for field in [nds, nds2, ep, eq]):
        messagebox.showerror(
            "Errore:",
            "I campi devono contenere solo numeri interi positivi senza lettere, punti o virgole.",
        )
        return

    # Conversione a interi, essendo sicuri che sono solo numeri interi positivi
    nds = int(nds)
    nds2 = int(nds2)
    ep = int(ep)
    eq = int(eq)
    if nds**ep < nds2**eq:
        chiave = nds2**eq - 1
        n = (nds**ep + 1) * (nds2**eq + 1)
        campo = chiave // (n % chiave)
    else:
        chiave = nds**ep - 1
        n = (nds**ep + 1) * (nds2**eq + 1)
        campo = chiave // (n % chiave)
    e6.delete(0, "end")
    e7.delete(0, "end")
    ic = int(log(campo, 2))
    ib = int(log(n, 2)) + 1
    e6.insert(0, str(ic))
    e7.insert(0, str(ib))


# **********************************************************
# *                Carica database esistente
# **********************************************************
def Carica_esistente():
    # Crea una finestra nascosta
    Croot = tk.Tk()
    Croot.withdraw()

    # Apri finestra di selezione file
    percorso_file = filedialog.askopenfilename(
        initialdir=drive_letter,
        title="Seleziona un file",
        filetypes=(("Tutti i file", "*.*"),),  # puoi filtrare per estensione
    )

    # Restituisci il percorso selezionato (o stringa vuota se annullato)
    if percorso_file=="":
        messagebox.showinfo("Attenzione","Caricamento annullato")
        Croot.destroy()
        return
    else:
        file_chiave=0
        apri= open(percorso_file, "r")
        c=int(apri.readline().strip())
        n1=int(apri.readline().strip())
        esp1=int(apri.readline().strip()) 
        n2=int(apri.readline().strip())
        esp2=int(apri.readline().strip())
        e1.delete(0, "end")
        e1.insert(0, str(n1))
        e11.delete(0, "end")
        e11.insert(0, str(n2))
        e3.delete(0, "end")
        e3.insert(0, str(esp1))     
        e4.delete(0, "end")
        e4.insert(0, str(esp2))
        apri.close()
        Croot.destroy()
        verifica()
        return  

# **********************************************************
# *                esegui calcolo
# **********************************************************

def esegui():
    nds = e1.get()
    nds2=e11.get()
    ep=e3.get()
    eq=e4.get()
    campo=e6.get()
    bit=e7.get()
    numero=e8.get()
    if nds=='' or nds2=='' or ep=='' or eq==''  or campo=='' or bit=='':
        messagebox.showerror('Attenzione:','tutti i campi devono essere compilati')
        return
    if numero=='':
        messagebox.askquestion('Attenzione',"Impostare numero numero semiprimi")
        return
    scrivis=cartella3+'/S'+bit+'b'
    scrivi = open(scrivis, "w")

    nd=int(nds)**int(ep)
    nd2=int(nds2)**int(eq)
    if nd<nd2:
        chiave=nd2-1
    else:
        chiave=nd-1    
    cnd = nd
    cnd2 = nd2
    for i in range(int(numero)):
        print("record N. ",i+1)
        tempo_inizio=time.time()
        nd = nextprime(cnd + randint(1, (2**int(campo))))
        tempo_fine=time.time()
        print(f"tempo in secondi Impiegato per p {tempo_fine-tempo_inizio}")
        tempo_inizio = time.time()
        nd2 = nextprime(cnd2 + randint(1, (2 ** int(campo))))
        tempo_fine = time.time()
        print(f"tempo in secondi Impiegato per q {tempo_fine-tempo_inizio}")
        n = nd * nd2
        a = n % chiave
        b = n - a
        r=gcd(a,b)
        if r==1:
            messagebox.showerror('Attenzione','Errore di campo')
            scrivi.close()
            return
        n=n+chiave
        scrivi.write(str(n)+'\n')
    scrivi.close()
    
    scrivi_usb=apri_dati+'chiave_S'+bit+'b'
    if os.path.exists(scrivi_usb):
        messagebox.showinfo("OK",'Database aggiornato')
        pass
    else:
        scrivi = open(scrivi_usb, "w")
        scrivi.write(str(chiave) + "\n")
        scrivi.write(str(nds) + "\n")
        scrivi.write(str(ep) + "\n")
        scrivi.write(str(nds2) + "\n")
        scrivi.write(str(eq) + "\n")

        scrivi.close()
        messagebox.showinfo('Creazione Database','Processo terminato correttamente')   


def on_enter(event):
    b1.config(
        bg=passa_button
    )  # Cambia il colore di sfondo a blu quando il mouse entra nel pulsante


def on_leave(event):
    b1.config(bg=fondo_button)  # Ripristina il colore di sfondo


def on_enter1(event):
    b2.config(
        bg=passa_button
    )  # Cambia il colore di sfondo a blu quando il mouse entra nel pulsante


def on_leave1(event):
    b2.config(bg=fondo_button)  # Ripristina il colore di sfondo


def on_enter2(event):
    b3.config(
        bg=passa_button
    )  # Cambia il colore di sfondo a blu quando il mouse entra nel pulsante


def on_leave2(event):
    b3.config(bg=fondo_button)  # Ripristina il colore di sfondo


# *************************************************
# *       dimensione e colori
# *************************************************
finestra_x = 600
finestra_y = 250
finestra = str(finestra_x) + "x" + str(finestra_y)
fondo_finestra = "#528B8B"
fondo_text = "#808080"
fondo_button = "#20B2AA"
passa_button = "#C0FF3E"
fondo_button2 = "#71C671"
fondo_entry = "#C1C1C1"
# *************************************************
# *        Finestra principale
# *************************************************
root = tk.Tk()
root.title("Crea Database Semiprimi p1*p2")
root.geometry(finestra)
root.config(bg=fondo_finestra)
# Creazione del canvas
px = finestra_x - 85
py = finestra_y - 85
canvas = tk.Canvas(root, width=90, height=90)
canvas.place(x=px, y=py)
px = 10
py = 10

l1=tk.Label(text='P1',bg=fondo_finestra,font='arial, 12 bold')
l1.place(x=px,y=py)
px=px+50
e1=tk.Entry(width=55,bg=fondo_button,font='arial, 12')
e1.place(x=px,y=py)
py=py+30
px=10
l11 = tk.Label(text="P2", bg=fondo_finestra, font="arial, 12 bold")
l11.place(x=px, y=py)
px = px + 50
e11 = tk.Entry(width=55, bg=fondo_button, font="arial, 12")
e11.place(x=px, y=py)


py=py+45
px=30

l3 = tk.Label(text="EP", bg=fondo_finestra, font="arial, 12 bold")
l3.place(x=px, y=py)
px = px + 30
e3 = tk.Entry(width=5, bg=fondo_button, font="arial, 12")
e3.place(x=px, y=py)

px = px + 60
l4 = tk.Label(text="EQ", bg=fondo_finestra, font="arial, 12 bold")
l4.place(x=px, y=py)
px = px + 30
e4 = tk.Entry(width=5, bg=fondo_button, font="arial, 12")
e4.place(x=px, y=py)

px = px + 70
l7 = tk.Label(text="Bit", bg=fondo_finestra, font="arial, 12 bold")
l7.place(x=px, y=py)
px = px + 30
e7 = tk.Entry(width=10, bg=fondo_button, font="arial, 12", justify="center")
e7.place(x=px, y=py)

px = px + 108
l8 = tk.Label(text="Numero", bg=fondo_finestra, font="arial, 12 bold")
l8.place(x=px, y=py)
px = px + 40
e8 = tk.Entry(width=5, bg=fondo_button, font="arial, 12")
e8.place(x=px, y=py)

py=py+50
px = 30
l6 = tk.Label(text="Campo", bg=fondo_finestra, font="arial, 12 bold")
l6.place(x=px, y=py)
px = px + 65
e6 = tk.Entry(width=10, bg=fondo_button, font="arial, 12", justify="center")
e6.place(x=px, y=py)


px = 10
py = py+70

b1 = tk.Button(
    root,
    text="Esegui",
    bg=fondo_button,
    font="arial, 12 bold",
    width=10,
    cursor="hand2",
    command=esegui
)
b1.place(x=px, y=py)
b1.bind("<Enter>", on_enter)
b1.bind("<Leave>", on_leave)

px=px+150
b2 = tk.Button(
    root,
    text="verifica",
    bg=fondo_button,
    font="arial, 12 bold",
    width=10,
    cursor="hand2",
    command=verifica,
)
b2.place(x=px, y=py)
b2.bind("<Enter>", on_enter1)
b2.bind("<Leave>", on_leave1)

px = px + 150
b3 = tk.Button(
    root,
    text="Carica Esistente",
    bg=fondo_button,
    font="arial, 12 bold",
    width=13,
    cursor="hand2",
    command=Carica_esistente,
)
b3.place(x=px, y=py)
b3.bind("<Enter>", on_enter2)
b3.bind("<Leave>", on_leave2)


testo = "Crea Db."
colore = "blue"  # Colore del testo
fonte = ("arial", 10, "bold")
colore_sfondo = fondo_finestra  # Colore dello sfondo
canvas.config(bg=colore_sfondo)
canvas.create_text(45, 20, text="GC57 QSO", fill="red", font=fonte)
canvas.create_text(45, 55, text=testo, fill=colore, font=fonte)


root.mainloop()
