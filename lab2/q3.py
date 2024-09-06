import time
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import binascii

def des_encrypt(plaintext, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), DES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def des_decrypt(ciphertext, key):
    cipher = DES.new(key.encode(), DES.MODE_ECB)
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    decrypted_plaintext = unpad(decrypted_padded_plaintext, DES.block_size)
    return decrypted_plaintext.decode()

def aes_encrypt(plaintext, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    padded_plaintext = pad(plaintext.encode(), AES.block_size)
    ciphertext = cipher.encrypt(padded_plaintext)
    return ciphertext

def aes_decrypt(ciphertext, key):
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    decrypted_padded_plaintext = cipher.decrypt(ciphertext)
    decrypted_plaintext = unpad(decrypted_padded_plaintext, AES.block_size)
    return decrypted_plaintext.decode()

# User inputs
message = input("Enter the message to encrypt: ")
des_key = input("Enter the DES key (8 characters): ")
aes_key = input("Enter the AES-256 key (32 characters): ")

# Ensure DES key is exactly 8 bytes and AES key is 32 bytes
if len(des_key) != 8:
    raise ValueError("DES key must be exactly 8 characters long.")
if len(aes_key) != 32:
    raise ValueError("AES-256 key must be exactly 32 characters long.")

# Measure time for DES encryption
start_time = time.time()
des_ciphertext = des_encrypt(message, des_key)
des_encrypt_time = time.time() - start_time

# Measure time for DES decryption
start_time = time.time()
des_decrypted_message = des_decrypt(des_ciphertext, des_key)
des_decrypt_time = time.time() - start_time

# Measure time for AES encryption
start_time = time.time()
aes_ciphertext = aes_encrypt(message, aes_key)
aes_encrypt_time = time.time() - start_time

# Measure time for AES decryption
start_time = time.time()
aes_decrypted_message = aes_decrypt(aes_ciphertext, aes_key)
aes_decrypt_time = time.time() - start_time

# Output the results
print("\nDES Encryption Time: {:.6f} seconds".format(des_encrypt_time))
print("DES Decryption Time: {:.6f} seconds".format(des_decrypt_time))
print("AES-256 Encryption Time: {:.6f} seconds".format(aes_encrypt_time))
print("AES-256 Decryption Time: {:.6f} seconds".format(aes_decrypt_time))

# Verify correctness of decryption
print("\nOriginal Message:", message)
print("DES Decrypted Message:", des_decrypted_message)
print("AES-256 Decrypted Message:", aes_decrypted_message)
