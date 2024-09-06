from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
import binascii

def triple_des_encrypt(plaintext, key):
    # Ensure the key is exactly 24 bytes (192 bits) for Triple DES
    if len(key) != 24:
        raise ValueError("The Triple DES key must be exactly 24 bytes long.")
    
    # Convert plaintext to bytes
    plaintext_bytes = plaintext.encode()
    
    # Create a Triple DES cipher object in ECB mode
    cipher = DES3.new(key.encode(), DES3.MODE_ECB)
    
    # Pad the plaintext to be a multiple of 8 bytes
    padded_plaintext = pad(plaintext_bytes, DES3.block_size)
    
    # Encrypt the padded plaintext
    ciphertext = cipher.encrypt(padded_plaintext)
    
    return ciphertext

def triple_des_decrypt(ciphertext, key):
    # Create a Triple DES cipher object in ECB mode
    cipher = DES3.new(key.encode(), DES3.MODE_ECB)
    
    # Decrypt the ciphertext
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    
    # Unpad the plaintext to retrieve the original message
    decrypted_plaintext = unpad(decrypted_padded_plaintext, DES3.block_size)
    
    return decrypted_plaintext.decode()

# Get user input for the key and message
key = input("Enter the Triple DES key (24 characters): ")
message = input("Enter the message to encrypt: ")

# Ensure the key is exactly 24 characters long
if len(key) != 24:
    raise ValueError("The Triple DES key must be exactly 24 characters long.")

# Encrypt the message
ciphertext = triple_des_encrypt(message, key)
print("Ciphertext (hex):", binascii.hexlify(ciphertext).decode())

# Decrypt the ciphertext
decrypted_message = triple_des_decrypt(ciphertext, key)
print("Decrypted message:", decrypted_message)
