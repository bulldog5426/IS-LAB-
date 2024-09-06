import time
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
import os

# RSA Functions
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def rsa_encrypt(message, public_key):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return base64.b64encode(encrypted_message).decode('utf-8')

def rsa_decrypt(encrypted_message, private_key):
    encrypted_message = base64.b64decode(encrypted_message)
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )
    return decrypted_message.decode('utf-8')

# ElGamal Functions
def generate_elgamal_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def elgamal_encrypt(message, public_key):
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    shared_secret = private_key.exchange(ec.ECDH(), public_key)
    
    # Derive AES key from shared secret
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(shared_secret)
    
    # Encrypt message
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    
    return base64.b64encode(iv + ciphertext).decode('utf-8'), private_key

def elgamal_decrypt(encrypted_message, private_key, public_key):
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
def measure_performance(encryption_func, decryption_func, key_gen_func, message):
    # Generate keys
    start_time = time.time()
    private_key, public_key = key_gen_func()
    key_gen_time = time.time() - start_time

    # Encrypt message
    start_time = time.time()
    encrypted_message, *rest = encryption_func(message, public_key)
    encryption_time = time.time() - start_time

    # Decrypt message
    start_time = time.time()
    decrypted_message = decryption_func(encrypted_message, private_key, public_key)
    decryption_time = time.time() - start_time
    
    return key_gen_time, encryption_time, decryption_time, decrypted_message

# Test with varying sizes of data
def run_tests():
    messages = [
        "Short message",
        "A bit longer message for performance testing.",
        "This message is a bit longer to evaluate performance of encryption and decryption processes. " * 10,  # 1 KB
        "A very large message" * 1000  # 10 KB
    ]
    
    for message in messages:
        print(f"Testing with message size: {len(message)} bytes")

        print("\nRSA:")
        rsa_results = measure_performance(rsa_encrypt, rsa_decrypt, generate_rsa_keys, message)
        print(f"Key Generation Time: {rsa_results[0]:.4f} seconds")
        print(f"Encryption Time: {rsa_results[1]:.4f} seconds")
        print(f"Decryption Time: {rsa_results[2]:.4f} seconds")
        assert message == rsa_results[3], "RSA decryption failed!"

        print("\nElGamal:")
        elgamal_results = measure_performance(elgamal_encrypt, elgamal_decrypt, generate_elgamal_keys, message)
        print(f"Key Generation Time: {elgamal_results[0]:.4f} seconds")
        print(f"Encryption Time: {elgamal_results[1]:.4f} seconds")
        print(f"Decryption Time: {elgamal_results[2]:.4f} seconds")
        assert message == elgamal_results[3], "ElGamal decryption failed!"

        print("-" * 50)

if __name__ == "__main__":
    run_tests()
