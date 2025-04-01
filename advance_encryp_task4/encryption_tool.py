import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

# Function to derive AES key from password
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

# Encrypt file
def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    cipher = Fernet(key)

    with open(file_path, "rb") as f:
        data = f.read()
    
    encrypted_data = cipher.encrypt(data)

    enc_file_path = file_path + ".enc"
    with open(enc_file_path, "wb") as f:
        f.write(salt + encrypted_data)
    
    return enc_file_path

# Decrypt file
def decrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        salt = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)
    cipher = Fernet(key)

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except Exception:
        return None  # Wrong password or tampered data

    dec_file_path = file_path.replace(".enc", "")
    with open(dec_file_path, "wb") as f:
        f.write(decrypted_data)
    
    return dec_file_path

# GUI Application
class EncryptionApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Encryption Tool")

        tk.Label(root, text="Select File:").pack(pady=5)
        self.file_path_entry = tk.Entry(root, width=50)
        self.file_path_entry.pack()
        tk.Button(root, text="Browse", command=self.browse_file).pack(pady=5)

        tk.Label(root, text="Enter Password:").pack(pady=5)
        self.password_entry = tk.Entry(root, show="*", width=30)
        self.password_entry.pack()

        tk.Button(root, text="Encrypt", command=self.encrypt).pack(pady=5)
        tk.Button(root, text="Decrypt", command=self.decrypt).pack(pady=5)

    def browse_file(self):
        file_path = filedialog.askopenfilename()
        self.file_path_entry.delete(0, tk.END)
        self.file_path_entry.insert(0, file_path)

    def encrypt(self):
        file_path = self.file_path_entry.get()
        password = self.password_entry.get()
        if file_path and password:
            enc_file = encrypt_file(file_path, password)
            messagebox.showinfo("Success", f"File Encrypted: {enc_file}")
        else:
            messagebox.showerror("Error", "Please provide a valid file and password")

    def decrypt(self):
        file_path = self.file_path_entry.get()
        password = self.password_entry.get()
        if file_path and password:
            dec_file = decrypt_file(file_path, password)
            if dec_file:
                messagebox.showinfo("Success", f"File Decrypted: {dec_file}")
            else:
                messagebox.showerror("Error", "Invalid password or corrupted file")

if __name__ == "__main__":
    root = tk.Tk()
    app = EncryptionApp(root)
    root.mainloop()
