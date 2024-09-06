import random
from sympy import mod_inverse

# ElGamal parameters
p = 7919
g = 2
h = 6465
x = 2999

def string_to_numbers(message):
    """Convert a string message to a list of integers."""
    return [ord(c) for c in message]

def numbers_to_string(numbers):
    """Convert a list of integers back to a string message."""
    return ''.join(chr(num) for num in numbers)

def encrypt_message(message):
    """Encrypt the message using ElGamal encryption."""
    numbers = string_to_numbers(message)
    ciphertext = []

    for m in numbers:
        k = random.randint(1, p - 1)  # Random integer k
        c1 = pow(g, k, p)            # Compute c1 = g^k mod p
        c2 = (m * pow(h, k, p)) % p  # Compute c2 = m * h^k mod p
        ciphertext.append((c1, c2))   # Append the tuple (c1, c2)

    return ciphertext

def decrypt_message(ciphertext):
    """Decrypt the ciphertext using ElGamal decryption."""
    plaintext_numbers = []

    for (c1, c2) in ciphertext:
        s = pow(c1, x, p)            # Compute s = c1^x mod p
        s_inv = mod_inverse(s, p)    # Compute the modular inverse of s
        m = (c2 * s_inv) % p         # Compute m = c2 * s_inv mod p
        plaintext_numbers.append(m)  # Append the plaintext number

    return numbers_to_string(plaintext_numbers)

# Test the ElGamal encryption and decryption
message = "Asymmetric Algorithms"

# Encrypt the message
ciphertext = encrypt_message(message)
print("Ciphertext:", ciphertext)

# Decrypt the message
decrypted_message = decrypt_message(ciphertext)
print("Decrypted Message:", decrypted_message)
