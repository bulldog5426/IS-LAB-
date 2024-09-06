from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii

def aes_encrypt(plaintext, key):
    # Ensure the key is exactly 16 bytes (128 bits)
    if len(key) != 16:
        raise ValueError("The key must be exactly 16 bytes long for AES-128.")
    
    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode()
    
    # Create an AES cipher object in ECB mode
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    
    # Pad the plaintext to be a multiple of 16 bytes
    padded_plaintext = pad(plaintext_bytes, AES.block_size)
    
    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return ciphertext

def aes_decrypt(ciphertext, key):
    # Create an AES cipher object in ECB mode
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    
    # Decrypt the ciphertext
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad the plaintext to retrieve the original message
    decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
    
    return decrypted_plaintext.decode()

# Get user input for the key and message
key = input("Enter the AES key (16 characters): ")
message = input("Enter the message to encrypt: ")

# Encrypt the message
ciphertext = aes_encrypt(message, key)
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())

# Decrypt the ciphertext
decrypted_message = aes_decrypt(ciphertext, key)
print("Decrypted message:", decrypted_message)
