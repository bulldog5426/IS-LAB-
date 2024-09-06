import time
import base64
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Function to generate ECC keys
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Function to encrypt message using ElGamal with ECC
def encrypt_message(message, public_key):
    # Generate a shared secret
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    
    # Derive an AES key from the shared secret
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(shared_secret)
    
    # Encrypt the message
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    
    return base64.b64encode(iv + ciphertext).decode('utf-8'), private_key

# Function to decrypt message using ElGamal with ECC
def decrypt_message(encrypted_message, private_key, public_key):
    # Generate the shared secret
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    
    # Derive the AES key from the shared secret
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(shared_secret)
    
    # Decrypt the message
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    
    return decrypted_message.decode('utf-8')

# Measure performance
def measure_performance(message):
    # Generate ECC keys
    private_key, public_key = generate_ecc_keys()
    
    # Measure encryption time
    start_time = time.time()
    encrypted_message, _ = encrypt_message(message, public_key)
    encryption_time = time.time() - start_time
    
    # Measure decryption time
    start_time = time.time()
    decrypted_message = decrypt_message(encrypted_message, private_key, public_key)
    decryption_time = time.time() - start_time
    
    print(f"Message Size: {len(message)} bytes")
    print(f"Encryption Time: {encryption_time:.4f} seconds")
    print(f"Decryption Time: {decryption_time:.4f} seconds")
    print(f"Decrypted Message: {decrypted_message}")

# Test with varying sizes of data
messages = [
    "Test message",
    "A bit longer test message to evaluate performance",
    "A much longer test message to thoroughly evaluate the performance of encryption and decryption processes",
    "A very large test message... " * 1000  # 1 MB
]

for message in messages:
    measure_performance(message)
    print("-" * 50)
