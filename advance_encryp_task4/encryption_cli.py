import os
import base64
import sys
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

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
    
    print(f"File Encrypted: {enc_file_path}")

def decrypt_file(file_path, password):
    with open(file_path, "rb") as f:
        salt = f.read(16)
        encrypted_data = f.read()

    key = derive_key(password, salt)
    cipher = Fernet(key)

    try:
        decrypted_data = cipher.decrypt(encrypted_data)
    except Exception:
        print("Error: Invalid password or corrupted file")
        return

    dec_file_path = file_path.replace(".enc", "")

    with open(dec_file_path, "wb") as f:
        f.write(decrypted_data)
    
    print(f"File Decrypted: {dec_file_path}")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 encryption_cli.py <encrypt/decrypt> <file_path> <password>")
        sys.exit(1)

    action, file_path, password = sys.argv[1], sys.argv[2], sys.argv[3]

    if action.lower() == "encrypt":
        encrypt_file(file_path, password)
    elif action.lower() == "decrypt":
        decrypt_file(file_path, password)
    else:
        print("Invalid command. Use 'encrypt' or 'decrypt'.")
