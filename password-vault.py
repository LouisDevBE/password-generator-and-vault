from array import array
from ctypes import alignment
import random
import sqlite3 
import hashlib
from sqlite3.dbapi2 import Cursor
from tkinter import *
from tkinter import simpledialog
from tkinter.font import Font
from functools import partial
import uuid
import pyperclip
import base64
import os
from tkinter import ttk
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
encryptionkey=0
def openVault():
    def on_closing():
        opnvault_btn['state']=NORMAL
        window2.destroy()
 
    backend=default_backend()
    salt=b'2444'
    kdf=PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=backend
    )
    def encrypt(message:bytes,key:bytes)-> bytes:
        return Fernet(key).encrypt(message)

    def decrypt(message:bytes,token:bytes)-> bytes:
        return Fernet(token).decrypt(message)

    with sqlite3.connect("password-vault.db") as db:
        cursor=db.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS masterpassword( 
    id INTEGER PRIMARY KEY,
    password TEXT NOT NULL,
    recoverykey TEXT NOT NULL);
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vault(
    id INTEGER PRIMARY KEY,
    ACCOUNT TEXT NOT NULL,
    USERNAME TEXT NOT NULL,
    PASSWORD TEXT NOT NULL);
    """)
    def popUp(text,previous_txt=""):
        answer=simpledialog.askstring("input string",prompt=text,initialvalue=str(previous_txt))
        return answer

    window2=Toplevel(window)
    window2.protocol("WM_DELETE_WINDOW",on_closing)
    
    window2.title("PASSWORD MANAGER")
    def hashPassword(input):
        # hash=hashlib.sha256(input)
        # hash=hash.hexdigest()
        return hashlib.sha256(input).hexdigest()

    def firstScreen():
        for widget in window2.winfo_children():
            widget.destroy()
        window2.geometry("250x150")

        lbl=ttk.Label(window2,text="Create Master Password")
        lbl.config(anchor=CENTER)
        lbl.pack()

        Mstr_pass_txt=ttk.Entry(window2,width=20,show="*")
        Mstr_pass_txt.pack()
        Mstr_pass_txt.focus()

        lbl1=ttk.Label(window2,text="Confirm Master Password")
        lbl1.pack() 
        
        Mstr_pass_txt2=ttk.Entry(window2,width=20,show="*")
        Mstr_pass_txt2.pack()
        
        
        lbl2=ttk.Label(window2,text="")
        lbl2.pack()

    
        def savePassword():
            if Mstr_pass_txt.get()==Mstr_pass_txt2.get() :
                sql="DELETE FROM masterpassword WHERE id=1"
                cursor.execute(sql)

                hashed_pass=hashPassword(Mstr_pass_txt.get().encode('utf-8'))
                key=str(uuid.uuid4().hex)
                
                recoverykey=hashPassword(key.encode('utf-8'))
                global encryptionkey 
                encryptionkey= base64.urlsafe_b64encode(kdf.derive("PremWagh2210".encode('utf-8')))
                
                insert_pass="""INSERT INTO masterpassword(password,recoverykey)
                VALUES(?,?)"""
                cursor.execute(insert_pass,((hashed_pass),(recoverykey)))
                db.commit()
                recoveryScreen(key)
            else:
                Mstr_pass_txt2.delete(0,'end')
                lbl2.config(text="TRY AGAIN !")



        btn=ttk.Button(window2,text="SAVE",command=savePassword)
        btn.pack(pady=10)

    def recoveryScreen(key):
        for widget in window2.winfo_children():
            widget.destroy()
        window2.geometry("250x150")

        lbl=ttk.Label(window2,text="Save Recovery Key")
        lbl.config(anchor=CENTER)
        lbl.pack()


        lbl1=ttk.Label(window2,text=key)
        lbl1.config(anchor=CENTER)
        lbl1.pack() 
        def copykey():
            pyperclip.copy(lbl1.cget("text"))
            
        btn=ttk.Button(window2,text="Copy key",command=copykey)
        btn.pack(pady=10)
        def done():
            passwordvault()
        btn=ttk.Button(window2,text="Done",command=done)
        btn.pack(pady=10)

    def resetScreen():
        for widget in window2.winfo_children():
            widget.destroy()
        window2.geometry("250x150")

        lbl=ttk.Label(window2,text="Enter Recovery Key")
        lbl.config(anchor=CENTER)
        lbl.pack()
        txt=ttk.Entry(window2,width=20)
        txt.pack()
        txt.focus()

        lbl1=ttk.Label(window2)
        lbl1.config(anchor=CENTER)
        lbl1.pack() 
        def getrecoverykey():
            recoverykeycheck=hashPassword((txt.get().encode('utf-8')))
            cursor.execute("SELECT * FROM masterpassword WHERE id=1 AND recoverykey=?",[(recoverykeycheck)])
            return cursor.fetchall()
            
    
        def checkRecovery():
            checked=getrecoverykey()
            if checked:
                firstScreen()
            else:
                txt.delete(0,'end')
                lbl1.config(text="wrong key")
        btn=ttk.Button(window2,text="Check key",command=checkRecovery)
        btn.pack(pady=10)

    def loginScreen():
        for widget in window2.winfo_children():
            widget.destroy()
        window2.geometry("250x150")

        lbl=ttk.Label(window2,text="Enter Master Password")
        lbl.config(anchor=CENTER)
        lbl.pack()

        Mstr_pass_txt=ttk.Entry(window2,width=20,show="*")
        Mstr_pass_txt.pack()
        Mstr_pass_txt.focus()

        lbl1=ttk.Label(window2,text="")
        lbl1.pack()
      
        def getMasterPassword():
            checkHashedpass = hashPassword(Mstr_pass_txt.get().encode('utf-8'))
            cursor.execute("SELECT * FROM masterpassword WHERE id=1 AND password=?",[(checkHashedpass)])
            return cursor.fetchall()
        
        def checkPassword():
  
        
            match=getMasterPassword()
            if match:
                global encryptionkey 
                encryptionkey= base64.urlsafe_b64encode(kdf.derive("PremWagh2210".encode('utf-8')))
                passwordvault()
            else:
                Mstr_pass_txt.delete(0,'end')
                lbl1.config(text="Wrong Password !")
               


        def resetPassword():
            resetScreen()
        login_btn=ttk.Button(window2,text="Login",command=checkPassword)
        login_btn.pack(pady=10)
        
        login_btn=ttk.Button(window2,text="Reset Password",command=resetPassword)
        login_btn.pack(pady=10)
    def passwordvault():
        for widget in window2.winfo_children():
            widget.destroy()
            
        def copyPass(password):
            password=decrypt(password, encryptionkey).decode('utf-8')
            pyperclip.copy(password)
        def copyursm(username):
            username=decrypt(username, encryptionkey).decode('utf-8')
            pyperclip.copy(username)
              
        
       
        def updateEntry(acc_id, account, username, password):
            prev_acc=decrypt(account, encryptionkey).decode('utf-8')
            prev_usnme=decrypt(username, encryptionkey).decode('utf-8')
            prev_pass=decrypt(password, encryptionkey).decode('utf-8')

            text1="UPDATE ACCOUNT"
            text2="UPDATE USERNAME"
            text3="UPDATE PASSWORD"
            account=encrypt(popUp(text1,prev_acc).encode('utf-8'),encryptionkey)
            username=encrypt(popUp(text2,prev_usnme).encode('utf-8'),encryptionkey)
            password=encrypt(popUp(text3,prev_pass).encode('utf-8'),encryptionkey)
            cursor.execute("UPDATE vault SET account=?, username=?, password=? WHERE id=?", (account,username,password,acc_id))
            db.commit()
            passwordvault()
        
        def addEntry():
            text1="ACCOUNT"
            text2="USERNAME"
            text3="PASSWORD"
            account=encrypt(popUp(text1).encode('utf-8'),encryptionkey)
            username=encrypt(popUp(text2).encode('utf-8'),encryptionkey)
            password=encrypt(popUp(text3).encode('utf-8'),encryptionkey)

            insert_feild="""INSERT INTO vault(account,username,password)
            VALUES(?,?,?) """
            cursor.execute(insert_feild,(account,username,password))
            db.commit()
            passwordvault()
            
            
        def removeEntry(input):
            cursor.execute("DELETE FROM vault WHERE id=?",(input,))
            db.commit()
            passwordvault()

        window2.geometry("870x450")
        # v=ttk.Scrollbar(window2,orient='vertical')
        # v.grid(row=0,column=8,sticky=NS)
        

        lbl=ttk.Label(window2,text="[ Password Vault ]",font ='arial 15 bold')
        lbl.grid(column=2,pady=20)
        
        
        add_entry_btn=ttk.Button(window2,text="ADD ENTRY",command=addEntry)
        add_entry_btn.grid(row=2,column=4,pady=10)
        lbl=ttk.Label(window2,text="ACCOUNT",font=Font(family='arial 10 bold', size=10))
        lbl.grid(row=2,column=0,padx=40)
        lbl=ttk.Label(window2,text="USERNAME",font=Font(family='arial 10 bold', size=10))
        lbl.grid(row=2,column=1,padx=40)
        lbl=ttk.Label(window2,text="PASSWORD",font=Font(family='arial 10 bold', size=10))
        lbl.grid(row=2,column=2,padx=40)
        cursor.execute("SELECT * FROM vault")
        if(cursor.fetchall()!=None):
            i=0
            cursor.execute("SELECT id,account,username,password FROM vault")
            
            for row in cursor.fetchall():
                acc_lab1=ttk.Label(window2,text=(decrypt(row[1],encryptionkey ) ) )
                acc_lab1.grid(column=0,row=i+3)
                ursm_lab1=ttk.Label(window2,text=(decrypt(row[2],encryptionkey ) ) )
                ursm_lab1.grid(column=1,row=i+3)
                pass_lab1=ttk.Label(window2,text='* '*len((decrypt(row[3],encryptionkey )) ) )
                pass_lab1.grid(column=2,row=i+3)

                dlete_btn=ttk.Button(window2,text="DELETE",command=partial(removeEntry,row[0]))
                dlete_btn.grid(column=3,row=i+3,pady=5)
                
                update_btn=ttk.Button(window2,text="UPDATE",command=partial(updateEntry,*row))
                update_btn.grid(column=4,row=i+3,pady=5)
                
                cpy_btn=ttk.Button(window2,text="COPY PASS",command=partial(copyPass,row[3]))
                cpy_btn.grid(column=5,row=i+3,pady=5)
                
                cpy_btn=ttk.Button(window2,text="COPY USERNAME",command=partial(copyursm,row[2]))
                cpy_btn.grid(column=6,row=i+3,pady=10)

                i+=1


    
    cursor.execute('SELECT * FROM masterpassword')
    if cursor.fetchall():
        loginScreen()
    else:
        firstScreen()
    
       
# ================================================(PASSWORD GENERATOR)=================================================================
window=Tk()
window.geometry('300x350')
window.style=ttk.Style(window)
window.title("PASSWORD GENERATOR")
# window.iconbitmap(True,'H:/prem college/qt_5.12/login_window_fl/login_img/f_logo.ico')
window.resizable(0,0)

no_of_letters=IntVar()
no_of_letters.set(3)
no_of_digits=IntVar()
no_of_digits.set(3)
no_of_symbols=IntVar()
no_of_symbols.set(3)

heading = ttk.Label(window, text = 'Password Generator' , font ='arial 15 bold').pack(pady=10)

letter_spinbox_label=ttk.Label(window,text="Select number of letters ",font=Font(family='arial 10 bold', size=10)).pack()
letter_spinbox=ttk.Spinbox(window,from_=3,to=11,textvariable=no_of_letters,width=5,font=Font(family='Helvetica', size=12)).pack()

digit_spinbox_label=ttk.Label(window,text="Select number of digits ",font=Font(family='arial 10 bold', size=10)).pack()
digit_spinbox=ttk.Spinbox(window,from_=3,to=11,textvariable=no_of_digits,width=5,font=Font(family='Helvetica', size=12)).pack()

symbol_spinbox_label=ttk.Label(window,text="Select number of symbols ",font=Font(family='arial 10 bold', size=10)).pack()
symbol_spinbox=ttk.Spinbox(window,from_=3,to=11,textvariable=no_of_symbols,width=5,font=Font(family='Helvetica', size=12)).pack()


password_string=StringVar()

def Copy_password():
    pyperclip.copy(password_string.get())
    copy['state']=DISABLED
def generate() :

    copy['state']=NORMAL
    password=[]
    digits=['1','2','3','4','5','6','7','8','9','0']
    letters=['a', 'b', 'c', 'd', 'e', 'f', 'g','h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',  'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z','A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z']
    symbols=['#','$','%','&','(',')','*','+','-','.','/',':','<','=','>','?','@','[',']','^','_','{','}','/' ]

    for x in range(no_of_letters.get()):
        password.append(random.choice(letters))
    for x in range(no_of_digits.get()):
        password.append(random.choice(digits))
    for x in range(no_of_symbols.get()):
        password.append(random.choice(symbols))
    
    random.shuffle(password)
    password_string.set("".join(password))


copy=ttk.Button(window, text = 'COPY', command = Copy_password,state=DISABLED)


def disablebtn():
    opnvault_btn['state']=DISABLED
    openVault()

opnvault_btn=ttk.Button(window,text="OPEN VAULT",command=disablebtn)
    
generate_pass=ttk.Button(window, text = "GENERATE PASSWORD" , command = generate).pack(pady=10)

ttk.Entry(window, textvariable=password_string).pack()

copy.pack(pady=10)

opnvault_btn.pack(pady=10)

window.mainloop()