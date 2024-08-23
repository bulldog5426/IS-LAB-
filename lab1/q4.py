import numpy as np

# Function to process the message (convert letters to numbers)
def process_message(message, block_size):
    message = message.replace(" ", "").upper()
    
    # Padding the message with 'X' if its length is not a multiple of block_size
    while len(message) % block_size != 0:
        message += 'X'
    
    # Convert characters to numbers (A=0, B=1, ..., Z=25)
    message_vector = [ord(char) - 65 for char in message]
    
    # Convert the list into a matrix (for easier matrix multiplication)
    return np.array(message_vector).reshape(-1, block_size)

# Function to convert numbers back to letters
def numbers_to_text(numbers):
    return ''.join(chr(num % 26 + 65) for num in numbers)

# Function to encipher using Hill Cipher
def hill_encrypt(message_matrix, key_matrix):
    # Multiply the message matrix by the key matrix and mod by 26
    encrypted_matrix = np.dot(message_matrix, key_matrix) % 26
    return encrypted_matrix.flatten()

# Function to decipher using Hill Cipher (Requires the inverse key matrix)
def hill_decrypt(cipher_matrix, inv_key_matrix):
    decrypted_matrix = np.dot(cipher_matrix, inv_key_matrix) % 26
    return decrypted_matrix.flatten()

# Helper function to calculate the modular inverse of the key matrix
def mod_matrix_inverse(matrix, modulus):
    determinant = int(np.round(np.linalg.det(matrix)))
    determinant_inv = pow(determinant, -1, modulus)
    matrix_mod_inv = determinant_inv * np.round(determinant * np.linalg.inv(matrix)).astype(int) % modulus
    return matrix_mod_inv

# Main program
def main():
    message = input("Enter the message to encipher: ")
    key_size = int(input("Enter the size of the key matrix (e.g., 2 for 2x2, 3 for 3x3): "))
    
    # Accept the key matrix from the user
    key_matrix = []
    print(f"Enter the {key_size}x{key_size} key matrix row by row (space-separated integers):")
    for i in range(key_size):
        row = list(map(int, input().split()))
        key_matrix.append(row)
    
    key_matrix = np.array(key_matrix)
    
    # Check if the determinant of the key matrix is non-zero and invertible modulo 26
    if np.linalg.det(key_matrix) == 0 or np.gcd(int(np.round(np.linalg.det(key_matrix))), 26) != 1:
        print("The provided key matrix is not invertible modulo 26. Please provide a valid key matrix.")
        return
    
    # Process the message
    message_matrix = process_message(message, key_size)

    # Encrypt the message
    encrypted_matrix = hill_encrypt(message_matrix, key_matrix)
    encrypted_message = numbers_to_text(encrypted_matrix)

    # Decrypt the message
    inv_key_matrix = mod_matrix_inverse(key_matrix, 26)
    decrypted_matrix = hill_decrypt(encrypted_matrix.reshape(-1, key_size), inv_key_matrix)
    decrypted_message = numbers_to_text(decrypted_matrix)

    print("\nKey Matrix:")
    print(key_matrix)
    print("\nEncrypted Message:", encrypted_message)
    print("Decrypted Message:", decrypted_message)

# Run the program
main()
