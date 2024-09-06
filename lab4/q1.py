from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

# Key Generation
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

def generate_dh_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Serialize keys
def serialize_key(key):
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def deserialize_key(serialized_key, key_type):
    return serialization.load_pem_public_key(serialized_key, backend=default_backend())

# Encrypt and Decrypt with RSA
def rsa_encrypt(public_key, plaintext):
    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext

def rsa_decrypt(private_key, ciphertext):
    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return plaintext

# Diffie-Hellman Key Exchange
def dh_key_exchange(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

# Main execution
def main():
    # Generate RSA key pairs
    rsa_private_key, rsa_public_key = generate_rsa_key_pair()
    print("RSA Public Key:", serialize_key(rsa_public_key).decode())

    # Generate DH parameters and key pairs
    dh_parameters = generate_dh_parameters()
    dh_private_key, dh_public_key = generate_dh_key_pair(dh_parameters)
    print("DH Public Key:", serialize_key(dh_public_key).decode())

    # Simulate key exchange
    shared_key = dh_key_exchange(dh_private_key, dh_public_key)
    print("Shared Key:", shared_key.hex())

    # Encrypt and decrypt a message
    message = b"Secure communication with RSA and DH"
    encrypted_message = rsa_encrypt(rsa_public_key, message)
    print("Encrypted Message:", encrypted_message.hex())

    decrypted_message = rsa_decrypt(rsa_private_key, encrypted_message)
    print("Decrypted Message:", decrypted_message.decode())

if __name__ == "__main__":
    main()
