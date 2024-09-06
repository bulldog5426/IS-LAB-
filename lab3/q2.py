from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import os

# Helper function to encrypt and decrypt using ECC
def ecc_encrypt_decrypt(message, private_key, public_key):
    # Generate a shared key using ECDH (Elliptic Curve Diffie-Hellman)
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    
    # Derive a key for encryption using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(shared_key)
    
    # Encrypt the message using AES
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    
    # Decrypt the message
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    
    return binascii.hexlify(ciphertext).decode('utf-8'), decrypted_message.decode()

# Generate ECC keys
private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
public_key = private_key.public_key()

# Export keys for display (optional)
private_pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

print("Private Key:", private_pem.decode())
print("Public Key:", public_pem.decode())

# Message to encrypt and decrypt
message_input = "Secure Transactions"

# Encrypt and decrypt
ciphertext, decrypted_message = ecc_encrypt_decrypt(message_input, private_key, public_key)

print(f"Ciphertext (hex): {ciphertext}")
print(f"Decrypted Message: {decrypted_message}")
