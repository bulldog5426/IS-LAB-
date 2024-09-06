from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

def des_encrypt(plaintext, key):
    # Ensure the key is exactly 8 bytes (64 bits)
    if len(key) != 8:
        raise ValueError("The key must be exactly 8 bytes long.")
    
    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode()
    
    # Create a DES cipher object in ECB mode
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    
    # Pad the plaintext to be a multiple of 8 bytes
    padded_plaintext = pad(plaintext_bytes, DES.block_size)
    
    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return ciphertext

def des_decrypt(ciphertext, key):
    # Create a DES cipher object in ECB mode
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    
    # Decrypt the ciphertext
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad the plaintext to retrieve the original message
    decrypted_plaintext = unpad(decrypted_padded_plaintext, DES.block_size)
    
    return decrypted_plaintext.decode()

# Get user input for the key and message
key = input("Enter the DES key (8 characters): ")
message = input("Enter the message to encrypt: ")

# Encrypt the message
ciphertext = des_encrypt(message, key)
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())

# Decrypt the ciphertext
decrypted_message = des_decrypt(ciphertext, key)
print("Decrypted message:", decrypted_message)
