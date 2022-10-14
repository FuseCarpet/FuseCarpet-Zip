from tkinter import *
import carpet as c
from carpet.carpet import genKey, encrypt, decrypt, encryptFile, decryptFile, gui
import carpet.file_operations as fo
import easygui
import pyperclip
import os

gui.terms2(terms='''By clicking "I agree", you agree to these terms:

    1. No distributing copies of this software on anywhere other than https://github.com/FuseCarpet unless allowed by rule 2.
    2. You are allowed to distribute this software IF IT IS MODIFIED and it does NOT make ANY money, with credits: Original made by FuseCarpet at https://github.com/FuseCarpet
''')

class _status:
    en_open = False
    de_open = False
    en_key = b''

root = Tk()
root.geometry("800x600")
root.title("FuseCarpet Zip")

m_key = genKey()

keylabel = Label(text="")
keylabel.pack()

copybtn = Button()

class cmds:
    def encrypt(key: str) -> None:
        if _status.en_open:
            return
        _status.en_open = True
        file = easygui.fileopenbox()
        _status.en_open = False
        if not file:
            return
        m_key = genKey()
        key = m_key
        keylabel.configure(text = f"Decryption Key: {bytes(key).decode('utf-8')}")
        encryptFile(file, key)
        copybtn.config(state=NORMAL)
        keylabel.pack()
        _status.en_key = key
    def decrypt(key: str) -> None:
        if _status.de_open:
            return
        _status.de_open = True
        file = easygui.fileopenbox()
        if not file:
            _status.de_open = False
            return
        r = easygui.enterbox('Decryption Key')
        print(r)
        _status.de_open = False
        if not r:
            return
        decryptFile(file, bytes(str(r), 'UTF-8'))
    def copyDecrypt():
        pyperclip.copy(_status.en_key.decode('UTF-8'))
    def iHash():
        choices = ['MD5', 'SHA256', 'SHA1', 'SHA224']
        r = easygui.choicebox("Select Hash Method", "Please Select Hash Method", choices)
        if not r:
            return
        _r = easygui.textbox("Please Type Text To Hash")
        if not _r:
            return
        
        elif r == 'MD5':
            ret = c.hash.md5(_r)
        elif r == 'SHA256':
            ret = c.hash.sha256(_r)
        elif r == 'SHA1':
            ret = c.hash.sha1(_r)
        elif r == 'SHA224':
            ret = c.hash.sha224(_r)
        
        easygui.msgbox(ret, "Hashed Text")
    def DownloadURL():
        _url = easygui.enterbox("Website URL")
        if not _url:
            return
        _out = easygui.filesavebox("Location To Download")
        if not os.path.isfile(_out):
            fo.write(_out, '')
        if not _url:
            return
        c.download(_url, _out)
        

Button(text="Encrypt File", command=lambda:cmds.encrypt(m_key)).pack()
Button(text="Decrypt File", command=lambda:cmds.decrypt(m_key)).pack()
Button(text="Hash Text", command=cmds.iHash).pack()
Button(text="Download file from URL", command=cmds.DownloadURL).pack()
copybtn = Button(text="Copy Decryption Key", command=cmds.copyDecrypt, state=DISABLED)
copybtn.pack()


root.mainloop()

