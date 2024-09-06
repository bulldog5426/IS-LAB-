from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Random import get_random_bytes
import binascii

# Function to encrypt and decrypt using AES in CTR mode
def aes_ctr_encrypt_decrypt(message, key, nonce):
    # Convert key and nonce from hex to bytes
    key_bytes = binascii.unhexlify(key)
    nonce_bytes = binascii.unhexlify(nonce)
    
    # Create a counter object with the nonce
    ctr = Counter.new(128, prefix=nonce_bytes, initial_value=0)
    
    # Create AES cipher in CTR mode
    cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
    
    # Encrypt the message
    ciphertext = cipher.encrypt(message.encode())
    ciphertext_hex = binascii.hexlify(ciphertext).decode('utf-8')
    
    # Decrypt the message (reinitialize the counter for decryption)
    ctr = Counter.new(128, prefix=nonce_bytes, initial_value=0)
    cipher = AES.new(key_bytes, AES.MODE_CTR, counter=ctr)
    decrypted_message = cipher.decrypt(ciphertext).decode()
    
    return ciphertext_hex, decrypted_message

# User inputs for AES-CTR
key_input = input("Enter the 32-byte AES key in hexadecimal (64 hex digits): ").strip()
nonce_input = input("Enter the 16-byte nonce in hexadecimal (32 hex digits): ").strip()
message_input = input("Enter the message to encrypt using AES-CTR: ").strip()

# Encrypt and decrypt
ciphertext, decrypted_message = aes_ctr_encrypt_decrypt(message_input, key_input, nonce_input)

print(f"AES-CTR Ciphertext: {ciphertext}")
print(f"AES-CTR Decrypted Message: {decrypted_message}")
