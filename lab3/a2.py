from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import base64

# Generate ECC keys
def generate_ecc_keys():
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Generate shared secret
def generate_shared_secret(private_key, peer_public_key):
    shared_secret = private_key.exchange(ec.ECDH(), peer_public_key)
    return shared_secret

# Encrypt message using AES
def encrypt_message(shared_secret, message):
    # Derive AES key from the shared secret
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
    return base64.b64encode(iv + ciphertext).decode('utf-8')

# Decrypt message using AES
def decrypt_message(shared_secret, encrypted_message):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]
    
    # Derive AES key from the shared secret
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=os.urandom(16),
        iterations=100000,
        backend=default_backend()
    )
    aes_key = kdf.derive(shared_secret)
    
    # Decrypt message
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted_message.decode('utf-8')

# Main function to execute ECC encryption and decryption
def main():
    # Generate key pairs for two peers
    private_key1, public_key1 = generate_ecc_keys()
    private_key2, public_key2 = generate_ecc_keys()
    
    # Generate shared secrets
    shared_secret1 = generate_shared_secret(private_key1, public_key2)
    shared_secret2 = generate_shared_secret(private_key2, public_key1)
    
    assert shared_secret1 == shared_secret2  # Ensure both peers have the same shared secret
    
    # Encrypt and decrypt message
    message = "Secure Transactions"
    encrypted_message = encrypt_message(shared_secret1, message)
    print("Encrypted Message:", encrypted_message)
    
    decrypted_message = decrypt_message(shared_secret2, encrypted_message)
    print("Decrypted Message:", decrypted_message)

if __name__ == "__main__":
    main()
