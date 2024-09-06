
from Crypto.Util import number
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Define RSA parameters
n = 323
e = 5
d = 173

# Define RSA public and private key
public_key = RSA.construct((n, e))
private_key = RSA.construct((n, e, d))

def encrypt_message(message, public_key):
    """Encrypt the message using the RSA public key."""
    encrypted_message = []
    for char in message:
        # Convert character to its numerical equivalent
        m = ord(char)
        # Encrypt using RSA formula: c = m^e % n
        c = pow(m, public_key.e, public_key.n)
        encrypted_message.append(c)
    return encrypted_message

def decrypt_message(encrypted_message, private_key):
    """Decrypt the message using the RSA private key."""
    decrypted_message = []
    for c in encrypted_message:
        # Decrypt using RSA formula: m = c^d % n
        m = pow(c, private_key.d, private_key.n)
        # Convert numerical equivalent back to character
        decrypted_message.append(chr(m))
    return ''.join(decrypted_message)

# Test encryption and decryption
message = "Cryptographic Protocols"

# Encrypt the message
encrypted_message = encrypt_message(message, public_key)
print("Encrypted Message:", encrypted_message)

# Decrypt the message
decrypted_message = decrypt_message(encrypted_message, private_key)
print("Decrypted Message:", decrypted_message)
