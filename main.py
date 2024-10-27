import getpass
from cryptography.fernet import Fernet
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import json
import os
from tkinter import Tk, filedialog, Label, Entry, Button, messagebox
import shutil
import stat
import win32security
import ntsecuritycon as con

ph = PasswordHasher()
encryption_key = None
logged_in_user = None

def hash_password(password):
    return ph.hash(password)

def verify_password(hashed_password, input_password):
    try:
        ph.verify(hashed_password, input_password)
        return True
    except VerifyMismatchError:
        return False

def generate_key():
    return Fernet.generate_key()

def load_user_data():
    with open("user_data.json", "r") as file:
        return json.load(file)

def save_user_data(username, hashed_password):
    user_data = {
        "username": username,
        "hashed_password": hashed_password
    }
    with open("user_data.json", "w") as file:
        json.dump(user_data, file)

def register():
    username = entry_username.get().strip()
    password = entry_password.get().strip()

    if not username or not password:
        messagebox.showerror("Fehler", "Benutzername und Passwort dürfen nicht leer sein!")
        return
    hashed_pw = hash_password(password)
    save_user_data(username, hashed_pw)
    messagebox.showinfo("Registrierung", "Registrierung erfolgreich!")

def login_menu():
    global encryption_key
    username = entry_username.get().strip()
    password = entry_password.get().strip()
    if not username or not password:
        messagebox.showerror("Fehler", "Benutzername und Passwort dürfen nicht leer sein!")
        return
    user_data = load_user_data()

    if username == user_data["username"] and verify_password(user_data["hashed_password"], password):
        logged_in_user = username
        user_folder = os.path.join(os.getcwd(), username)
        key_file = os.path.join(user_folder, 'encryption.key')

        if not os.path.exists(user_folder):
            os.makedirs(user_folder)
            encryption_key = generate_key()
            with open(key_file, 'wb') as f:
                f.write(encryption_key)
                messagebox.showinfo("Login", "Benutzerordner erstellt!")
                set_folder_permissions(user_folder)
        else:
            with open(key_file, 'rb') as f:
                encryption_key = f.read()
        messagebox.showinfo("Login", "Login erfolgreich!")
    else:
        messagebox.showerror("Login", "Falscher Benutzername oder Passwort")

def encrypt_data():
    global encryption_key

    if encryption_key is None:
        messagebox.showerror("Fehler", "Bitte zuerst einloggen!")
        return
    
    file_path = filedialog.askopenfilename()
    if not file_path:
        return
    
    user_folder = os.path.join(os.getcwd(), logged_in_user)

    cipher = Fernet(encryption_key)

    with open(file_path, 'rb') as f:
        file_data = f.read()

    encrypted_data = cipher.encrypt(file_data)

    filename = os.path.basename(file_path)
    encrypted_file_path = os.path.join(user_folder, "encrypted_" + filename + '.enc')

    with open(encrypted_file_path, 'wb') as f:
        f.write(encrypted_data)
    messagebox.showinfo("Verschlüsselung", f"{filename} erfolgreich verschlüsselt!")

def set_folder_permissions(folder_path):
    sd = win32security.GetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION)
    user, domain, _ = win32security.LookupAccountName("", os.getlogin())
    dacl = win32security.ACL()
    dacl.AddAccessAllowedAce(win32security.ACL_REVISION, con.FILE_ALL_ACCESS, user)
    sd.SetSecurityDescriptorDacl(1, dacl, 0)
    win32security.SetFileSecurity(folder_path, win32security.DACL_SECURITY_INFORMATION, sd)

def decrypt_data():
    global encryption_key

    if encryption_key is None:
        messagebox.showerror("Fehler", "Bitte zuerst einloggen!")
        return
    
    encrypted_file_path = filedialog.askopenfilename()
    if not encrypted_file_path:
        return

    cipher = Fernet(encryption_key)

    try:
        with open(encrypted_file_path, 'rb') as f:
            encrypted_data = f.read()

        decrypted_data = cipher.decrypt(encrypted_data)
        filename = os.path.basename(encrypted_file_path)
        if filename.startswith('encrypted_'):
            filename = filename[len("encrypted_"):]
        if filename.endswith('.enc'):
            filename = filename[:-4]
        decrypted_file_path = os.path.join(os.getcwd(), filename)

        with open(decrypted_file_path, 'wb') as f:
            f.write(decrypted_data)
        messagebox.showinfo("Entschlüsselung", f"{filename} erfolgreich entschlüsselt!")
    
    except Exception as e:
        messagebox.showerror("Fehler", f"Fehler beim Entschlüsseln: {e}")

root = Tk()
root.title("Datei-Verschlüsselungs-App")
root.geometry("600x400")

Label(root, text="Benutzername:").grid(row=0, column=0)
entry_username = Entry(root)
entry_username.grid(row=0, column=1)

Label(root, text="Passwort:").grid(row=1, column=0)
entry_password = Entry(root, show="*")
entry_password.grid(row=1, column=1)

Button(root, text="Registrieren", command=register).grid(row=2, column=0)
Button(root, text="Login", command=login_menu).grid(row=2, column=1)

Button(root, text="Datei verschlüsseln", command=encrypt_data).grid(row=3, column=0)
Button(root, text="Datei entschlüsseln", command=decrypt_data).grid(row=3, column=1)


if __name__ == '__main__':
    root.mainloop()