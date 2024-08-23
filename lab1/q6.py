import numpy as np

# Helper function to find modular inverse of a under mod 26
def mod_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

# Function to decrypt using Affine Cipher with a given a and b
def affine_decrypt(ciphertext, a, b):
    decrypted_message = ""
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return None  # No modular inverse, skip this pair
    
    for char in ciphertext:
        if char.isalpha():
            y = ord(char) - 65  # Convert letter to number (A=0, B=1, ..., Z=25)
            x = (a_inv * (y - b)) % 26  # Apply decryption formula
            decrypted_message += chr(x + 65)  # Convert number back to letter
        else:
            decrypted_message += char  # Non-alphabet characters remain the same
    
    return decrypted_message

# Brute-force attack
def brute_force_affine(ciphertext, known_plaintext, known_ciphertext):
    p1, p2 = known_plaintext
    c1, c2 = known_ciphertext
    p1_num = ord(p1) - 65
    p2_num = ord(p2) - 65
    c1_num = ord(c1) - 65
    c2_num = ord(c2) - 65
    
    # Try all possible values of a and b
    for a in range(1, 26):
        if np.gcd(a, 26) == 1:  # Check if a is coprime with 26
            for b in range(0, 26):
                # Check if the affine cipher with this a and b transforms the known plaintext to known ciphertext
                if (a * p1_num + b) % 26 == c1_num and (a * p2_num + b) % 26 == c2_num:
                    print(f"Possible keys: a = {a}, b = {b}")
                    decrypted_message = affine_decrypt(ciphertext, a, b)
                    if decrypted_message:
                        print(f"Decrypted Message: {decrypted_message}\n")

# Known values and ciphertext
ciphertext = "XPALASXYFGFUKPXUSOGEUTKCDGEXANMGNVS"
known_plaintext = "AB"
known_ciphertext = "GL"

# Brute-force attack
brute_force_affine(ciphertext, known_plaintext, known_ciphertext)
