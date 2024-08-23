import string

# Function to generate the Playfair cipher key matrix
def generate_key_matrix(key):
    # Remove duplicates from the key
    key = ''.join(sorted(set(key), key=key.index))
    
    # Create a key square matrix (5x5)
    matrix = []
    used_letters = set()
    alphabet = string.ascii_uppercase.replace('J', '')  # Use 'I' and 'J' as the same letter

    for char in key:
        if char not in used_letters and char.isalpha():
            used_letters.add(char)
            matrix.append(char)

    for char in alphabet:
        if char not in used_letters:
            matrix.append(char)

    return [matrix[i * 5:(i + 1) * 5] for i in range(5)]

# Function to process the message (remove spaces, handle duplicate letters)
def process_message(message):
    message = message.replace(" ", "").upper()
    processed_message = ""
    i = 0
    while i < len(message):
        processed_message += message[i]
        if i + 1 < len(message) and message[i] == message[i + 1]:
            processed_message += 'X'
        else:
            if i + 1 < len(message):
                processed_message += message[i + 1]
            i += 1
        i += 2

    # If the message length is odd, add 'X' to the end
    if len(processed_message) % 2 != 0:
        processed_message += 'X'
    
    return processed_message

# Function to find position of letters in the matrix
def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None, None

# Function to encipher using Playfair Cipher
def playfair_encrypt(matrix, message):
    ciphertext = ""
    for i in range(0, len(message), 2):
        row1, col1 = find_position(matrix, message[i])
        row2, col2 = find_position(matrix, message[i + 1])

        if row1 == row2:
            ciphertext += matrix[row1][(col1 + 1) % 5] + matrix[row2][(col2 + 1) % 5]
        elif col1 == col2:
            ciphertext += matrix[(row1 + 1) % 5][col1] + matrix[(row2 + 1) % 5][col2]
        else:
            ciphertext += matrix[row1][col2] + matrix[row2][col1]
    
    return ciphertext

# Function to decipher using Playfair Cipher
def playfair_decrypt(matrix, ciphertext):
    plaintext = ""
    for i in range(0, len(ciphertext), 2):
        row1, col1 = find_position(matrix, ciphertext[i])
        row2, col2 = find_position(matrix, ciphertext[i + 1])

        if row1 == row2:
            plaintext += matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
        elif col1 == col2:
            plaintext += matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
        else:
            plaintext += matrix[row1][col2] + matrix[row2][col1]
    
    return plaintext

# Main program
def main():
    key = input("Enter the secret key for Playfair cipher: ").replace(" ", "").upper()
    message = input("Enter the message to encipher: ")

    key_matrix = generate_key_matrix(key)
    processed_message = process_message(message)

    print("\nPlayfair Cipher Key Matrix:")
    for row in key_matrix:
        print(" ".join(row))
    
    encrypted_message = playfair_encrypt(key_matrix, processed_message)
    decrypted_message = playfair_decrypt(key_matrix, encrypted_message)

    print("\nProcessed Message:", processed_message)
    print("Encrypted Message:", encrypted_message)
    print("Decrypted Message:", decrypted_message)

# Run the program
main()
