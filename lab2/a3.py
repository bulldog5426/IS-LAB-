from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii

# AES-256 Encryption and Decryption
def aes_encrypt_decrypt(message, key):
    cipher = AES.new(key, AES.MODE_ECB)
    padded_message = pad(message.encode(), AES.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_message)
    ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')
    
    # Decrypt
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_padded_message = cipher.decrypt(ciphertext)
    decrypted_message = unpad(decrypted_padded_message, AES.block_size).decode()
    
    return ciphertext_hex, decrypted_message

# DES Encryption (CBC Mode) and Decryption
def des_encrypt_decrypt(message, key, iv):
    cipher = DES.new(key, DES.MODE_CBC, iv)
    padded_message = pad(message.encode(), DES.block_size)
    
    # Encrypt
    ciphertext = cipher.encrypt(padded_message)
    ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')
    
    # Decrypt
    cipher = DES.new(key, DES.MODE_CBC, iv)
    decrypted_padded_message = cipher.decrypt(ciphertext)
    decrypted_message = unpad(decrypted_padded_message, DES.block_size).decode()
    
    return ciphertext_hex, decrypted_message

# Get user input for AES-256
aes_key_input = input("Enter the 32-byte AES-256 key in hexadecimal (64 hex digits): ").strip()
message_aes = input("Enter the message to encrypt using AES-256: ").strip()
aes_key = binascii.unhexlify(aes_key_input)

# Get user input for DES CBC mode
des_key_input = input("Enter the 8-byte DES key in hexadecimal (16 hex digits): ").strip()
iv_input = input("Enter the 8-byte IV in hexadecimal (16 hex digits): ").strip()
message_des = input("Enter the message to encrypt using DES in CBC mode: ").strip()
des_key = binascii.unhexlify(des_key_input)
iv = binascii.unhexlify(iv_input)

# Perform AES-256 encryption and decryption
aes_ciphertext, aes_decrypted_message = aes_encrypt_decrypt(message_aes, aes_key)
print(f"AES-256 Ciphertext: {aes_ciphertext}")
print(f"AES-256 Decrypted Message: {aes_decrypted_message}")

# Perform DES CBC encryption and decryption
des_ciphertext, des_decrypted_message = des_encrypt_decrypt(message_des, des_key, iv)
print(f"DES CBC Ciphertext: {des_ciphertext}")
print(f"DES CBC Decrypted Message: {des_decrypted_message}")
