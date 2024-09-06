from sympy import mod_inverse, isprime
import random

def elgamal_encrypt_decrypt(p, g, h, x, message):
    # Convert message to integer (ASCII encoding)
    m = int.from_bytes(message.encode(), 'big')
    
    # Encryption
    k = random.randint(1, p - 2)  # Random integer k
    c1 = pow(g, k, p)            # c1 = g^k % p
    c2 = (m * pow(h, k, p)) % p  # c2 = m * h^k % p
    
    # Decryption
    c1_x = pow(c1, x, p)          # c1^x % p
    c1_x_inv = mod_inverse(c1_x, p)  # Modular inverse of c1^x % p
    m_decrypted = (c2 * c1_x_inv) % p  # m = c2 * (c1^x)^-1 % p
    
    # Convert integer back to message
    message_decrypted = m_decrypted.to_bytes((m_decrypted.bit_length() + 7) // 8, 'big').decode()
    
    return (c1, c2), message_decrypted

# Define the public and private keys
p = 3233  # Example prime number (should be large in practice)
g = 2     # Example generator (should be chosen appropriately)
x = 15    # Example private key (should be kept secret)
h = pow(g, x, p)  # Compute h = g^x % p

# Message to encrypt and decrypt
message_input = "Confidential Data"

# Perform encryption and decryption
ciphertext, decrypted_message = elgamal_encrypt_decrypt(p, g, h, x, message_input)

print(f"Ciphertext: {ciphertext}")
print(f"Decrypted Message: {decrypted_message}")
