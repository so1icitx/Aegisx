from cryptography.fernet import Fernet
import os

# Create secret.key file for Fernet encryption if it doesn't exist
def init_secret_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)
        print("[AegisX] Generated new encryption key: secret.key")
    else:
        print("[AegisX] Using existing encryption key: secret.key")

# Get Fernet instance with secret key
def get_fernet():
    try:
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
        return Fernet(key)
    except FileNotFoundError:
        init_secret_key()
        with open("secret.key", "rb") as key_file:
            key = key_file.read()
        return Fernet(key)

# Encrypt a string value
def encrypt_data(data: str) -> str:
    if data is None:
        return None
    return get_fernet().encrypt(data.encode()).decode()

# Decrypt a string value
def decrypt_data(data: str) -> str:
    if data is None:
        return None
    try:
        return get_fernet().decrypt(data.encode()).decode()
    except Exception:
        return "[Decryption Error]"
