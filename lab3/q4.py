import os
import time
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Helper function to read file content
def read_file(file_path):
    with open(file_path, 'rb') as f:
        return f.read()

# RSA Key Generation
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

# RSA Encryption/Decryption
def rsa_encrypt_decrypt(file_path, private_key, public_key):
    data = read_file(file_path)
    
    # Generate AES key
    aes_key = os.urandom(32)
    cipher = Cipher(algorithms.AES(aes_key), modes.EAX(os.urandom(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Decryption
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    return ciphertext, decrypted_data

# ECC Key Generation
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# ECC Encryption/Decryption
def ecc_encrypt_decrypt(file_path, private_key, public_key):
    data = read_file(file_path)
    
    # Compute shared key
    shared_key = private_key.exchange(ec.ECDH(), public_key)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(shared_key)
    
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(os.urandom(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(data) + encryptor.finalize()
    
    # Decryption
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    return ciphertext, decrypted_data

# Measure performance for RSA
def measure_rsa_performance(file_path):
    start_time = time.time()
    private_key, public_key = generate_rsa_keys()
    key_gen_time = time.time() - start_time

    start_time = time.time()
    ciphertext, decrypted_data = rsa_encrypt_decrypt(file_path, private_key, public_key)
    encryption_time = time.time() - start_time

    return key_gen_time, encryption_time, decrypted_data

# Measure performance for ECC
def measure_ecc_performance(file_path):
    start_time = time.time()
    private_key, public_key = generate_ecc_keys()
    key_gen_time = time.time() - start_time

    start_time = time.time()
    ciphertext, decrypted_data = ecc_encrypt_decrypt(file_path, private_key, public_key)
    encryption_time = time.time() - start_time

    return key_gen_time, encryption_time, decrypted_data

# Main function to execute the performance tests
def main():
    file_path = 'sample_file.txt'  # Path to the file for testing

    # RSA Performance
    rsa_key_gen_time, rsa_enc_time, rsa_decrypted_data = measure_rsa_performance(file_path)
    print(f"RSA Key Generation Time: {rsa_key_gen_time:.2f} seconds")
    print(f"RSA Encryption Time: {rsa_enc_time:.2f} seconds")

    # ECC Performance
    ecc_key_gen_time, ecc_enc_time, ecc_decrypted_data = measure_ecc_performance(file_path)
    print(f"ECC Key Generation Time: {ecc_key_gen_time:.2f} seconds")
    print(f"ECC Encryption Time: {ecc_enc_time:.2f} seconds")

    # Verify decryption correctness
    with open(file_path, 'rb') as f:
        original_data = f.read()
    assert original_data == rsa_decrypted_data
    assert original_data == ecc_decrypted_data
    print("Decryption successful. Original data matches decrypted data.")

if __name__ == "__main__":
    main()
