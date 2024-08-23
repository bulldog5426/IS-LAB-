def decrypt_additive_cipher(ciphertext, shift):
    decrypted_message = ""
    
    for char in ciphertext:
        if char.isalpha():  # Only decrypt alphabetic characters
            # Convert letter to number (A=0, ..., Z=25)
            char_num = ord(char.upper()) - 65
            # Decrypt using the additive cipher formula
            decrypted_char = chr((char_num - shift) % 26 + 65)
            decrypted_message += decrypted_char
        else:
            # Keep non-alphabetic characters as they are
            decrypted_message += char
    
    return decrypted_message

# Main function to brute-force all possible shifts
def brute_force_additive(ciphertext):
    for shift in range(1, 26):  # Try all possible shifts from 1 to 25
        decrypted_message = decrypt_additive_cipher(ciphertext, shift)
        print(f"Shift {shift}: {decrypted_message}")

# Ciphertext
ciphertext = "NCJAEZRCLAS/LYODEPRLYZRCLASJLCPEHZDTOPDZOLN&BY"

# Perform brute-force attack
brute_force_additive(ciphertext)
