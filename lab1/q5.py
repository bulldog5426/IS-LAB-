# Function to determine the shift used in a shift cipher
def determine_shift(known_ciphertext, known_plaintext):
    shifts = []
    for i in range(len(known_ciphertext)):
        # Calculate the shift by comparing each letter in the ciphertext and plaintext
        shift = (ord(known_ciphertext[i]) - ord(known_plaintext[i])) % 26
        shifts.append(shift)
    
    # Assuming all shifts are the same (as it's a shift cipher)
    if len(set(shifts)) == 1:
        return shifts[0]
    else:
        return None

# Function to decrypt a ciphertext using a shift
def decrypt_shift_cipher(ciphertext, shift):
    decrypted_message = ""
    for char in ciphertext:
        if char.isalpha():
            decrypted_char = chr((ord(char) - shift - 65) % 26 + 65)
            decrypted_message += decrypted_char
        else:
            decrypted_message += char
    return decrypted_message

# Main function
def main():
    # User inputs
    known_ciphertext = input("Enter the known ciphertext: ").upper()
    known_plaintext = input("Enter the known plaintext: ").upper()
    unknown_ciphertext = input("Enter the ciphertext from the tablet: ").upper()

    # Determine the shift
    shift = determine_shift(known_ciphertext, known_plaintext)
    
    if shift is None:
        print("Error: Unable to determine a consistent shift.")
    else:
        print(f"\nThe shift identified from the known plaintext and ciphertext is: {shift}")
        
        # Decrypt the unknown ciphertext
        decrypted_message = decrypt_shift_cipher(unknown_ciphertext, shift)
        print(f"\nDecrypted message from the tablet: {decrypted_message}")
        print("\nType of attack: Known Plaintext Attack")

# Run the program
main()
