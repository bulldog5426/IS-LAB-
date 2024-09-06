from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import binascii

def rsa_encrypt_decrypt(message, public_key, private_key):
    # Encrypt the message
    cipher_rsa = PKCS1_OAEP.new(public_key)
    ciphertext = cipher_rsa.encrypt(message.encode())
    ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')
    
    # Decrypt the message
    cipher_rsa = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher_rsa.decrypt(ciphertext).decode()
    
    return ciphertext_hex, decrypted_message

# Generate RSA keys
key = RSA.generate(2048)
public_key = key.publickey()
private_key = key

# Example public and private key extraction (not required if keys are generated as above)
# public_key = RSA.construct((n, e))  # Example public key values
# private_key = RSA.construct((n, d)) # Example private key values

# Message to encrypt and decrypt
message_input = "Asymmetric Encryption"

# Encrypt and decrypt
ciphertext, decrypted_message = rsa_encrypt_decrypt(message_input, public_key, private_key)

print(f"Ciphertext (hex): {ciphertext}")
print(f"Decrypted Message: {decrypted_message}")
