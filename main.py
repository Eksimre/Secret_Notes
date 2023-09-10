from tkinter import *
from tkinter import messagebox
import base64

#enctption
def encode(key, clear):
    enc = []
    for i in range(len(clear)):
        key_c = key[i % len(key)]
        enc_c = chr((ord(clear[i]) + ord(key_c)) % 256)
        enc.append(enc_c)
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode (key, enc):
    dec = []
    enc = base64.urlsafe_b64decode(enc).decode()
    for i in range(len(enc)):
        key_c = key[i % len(key)]
        dec_c = chr((256 + ord(enc[i]) - ord(key_c)) % 256)
        dec.append(dec_c)
    return "".join(dec)


#dosya oluşturma
dosya = open("Secret_File.txt","a")
open("C:\\Users\\eksim\Desktop\\Pyton Eğitim ve Projeler\\pychram dersler\\Secret_Notes_Project\Secret_File.txt", "a")


window = Tk()
window.title("Secret notes")
window.minsize(width=400, height=700)
window.config(padx=40, pady=40)

def gizlenecek_bilgi():
    başlık = (başlık_entry.get())
    içerik = (gizli_içerik.get(1.0, END))
    anahtar = (içerik_anahtarı.get())
    print(başlık + içerik)
    dosya = open("Secret_File.txt", "a")
    #dosya.write(başlık +"\n"+ içerik)
    başlık_entry.delete(0, "end")
    gizli_içerik.delete(1.0, "end")
    içerik_anahtarı.delete(0,"end")

    if başlık == "" or içerik == "" or anahtar == "":
        messagebox.showinfo(title="Hata!", message="Lüften alanları doldurunuz!")
    else:
        message_encrypted = encode(anahtar, içerik)
        dosya.write("\n" + başlık + "\n" + f"{message_encrypted}")

def çözülecek_şifre():
    message_encrypted = (gizli_içerik.get(1.0, END))
    anahtar = içerik_anahtarı.get()

    if message_encrypted == "" or anahtar == "":
        messagebox.showinfo(title="Hata!", message="Lüften alanları doldurunuz!")
    else:
        decrypted_message = decode(anahtar, message_encrypted)
        gizli_içerik.delete(1.0, "end")
        gizli_içerik.insert(1.0, decrypted_message)


icon = PhotoImage(file= "tops.png")
icon_ = Label(image=icon)
icon_.config(bg="dark red")
icon_.pack()

başlık_girin = Label(text="İçerik Başlığı Giriniz", font=("Ariel", 12, "bold"))
başlık_girin.config(pady=(10))
başlık_girin.pack()
başlık_entry = Entry(width=35)
başlık_entry.pack()

içerik_girin = Label(text="Gizlenecek İçeriği Giriniz.", font=("Ariel", 12, "bold"))
içerik_girin.config(pady=(10))
içerik_girin.pack()
gizli_içerik = Text(width=40, height=15)
gizli_içerik.pack()

içerik_anahtarı_girin = Label(text="İçerik Anahtarı Giriniz.", font=("Ariel", 12, "bold"))
içerik_anahtarı_girin.pack()
içerik_anahtarı_girin.config(pady=(10))
içerik_anahtarı = Entry(width=35)
içerik_anahtarı.pack()

#butonlar

kaydet_şifrele = Button(text="Kaydet ve Şifrele", command=gizlenecek_bilgi )
kaydet_şifrele.config(font=("Ariel", 8, "bold"))
kaydet_şifrele.config(pady=5)
kaydet_şifrele.pack()

şifreyi_çöz = Button(text="Şifreyi Çöz", command=çözülecek_şifre)
şifreyi_çöz.config(font=("Ariel", 8, "bold"))
şifreyi_çöz.pack()


dosya.close()
window.mainloop()
