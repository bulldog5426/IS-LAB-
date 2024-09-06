from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

def aes_encrypt(plaintext, key):
    # Ensure the key is 24 bytes (192 bits)
    if len(key) != 24:
        raise ValueError("AES-192 key must be exactly 24 bytes long.")
    
    # Create AES cipher object in ECB mode
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    
    # Pad the plaintext to be a multiple of 16 bytes
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    
    # Encrypt the plaintext
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return ciphertext

def aes_decrypt(ciphertext, key):
    # Create AES cipher object in ECB mode
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    
    # Decrypt the ciphertext
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad the plaintext to retrieve the original message
    decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
    
    return decrypted_plaintext.decode()

# User inputs
key = input("Enter the AES-192 key (24 characters): ")
message = input("Enter the message to encrypt: ")

# Ensure the key is exactly 24 characters long
if len(key) != 24:
    raise ValueError("The AES-192 key must be exactly 24 characters long.")

# Encrypt the message
ciphertext = aes_encrypt(message, key)
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())

# Decrypt the ciphertext
decrypted_message = aes_decrypt(ciphertext, key)
print("Decrypted message:", decrypted_message)
