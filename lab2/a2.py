from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import binascii

# Get user input for the key and plaintext blocks
key_input = input("Enter the 8-byte key in hexadecimal (16 hex digits): ").strip()
block1_input = input("Enter the first block in hexadecimal: ").strip()
block2_input = input("Enter the second block in hexadecimal: ").strip()

# Convert the key from hex to bytes
key = binascii.unhexlify(key_input)

# Convert the blocks from hex to bytes
block1 = binascii.unhexlify(block1_input)
block2 = binascii.unhexlify(block2_input)

# Ensure key length is 8 bytes (DES requirement)
if len(key) != 8:
    raise ValueError("Key must be 8 bytes long.")

# Encrypt the blocks using DES in ECB mode
cipher = DES.new(key, DES.MODE_ECB)

# Pad the blocks if necessary (DES works on 8-byte blocks)
block1_padded = pad(block1, DES.block_size)
block2_padded = pad(block2, DES.block_size)

# Encrypt the blocks
ciphertext_block1 = cipher.encrypt(block1_padded)
ciphertext_block2 = cipher.encrypt(block2_padded)

# Convert ciphertext to hex for display
ciphertext_block1_hex = binascii.hexlify(ciphertext_block1).decode('utf-8')
ciphertext_block2_hex = binascii.hexlify(ciphertext_block2).decode('utf-8')

print(f"Ciphertext for Block 1: {ciphertext_block1_hex}")
print(f"Ciphertext for Block 2: {ciphertext_block2_hex}")

# Decrypt the blocks to retrieve original plaintext
decrypted_block1 = unpad(cipher.decrypt(ciphertext_block1), DES.block_size)
decrypted_block2 = unpad(cipher.decrypt(ciphertext_block2), DES.block_size)

# Convert decrypted plaintext back to hex for display
decrypted_block1_hex = binascii.hexlify(decrypted_block1).decode('utf-8')
decrypted_block2_hex = binascii.hexlify(decrypted_block2).decode('utf-8')

print(f"Decrypted Block 1 (Hex): {decrypted_block1_hex}")
print(f"Decrypted Block 2 (Hex): {decrypted_block2_hex}")
