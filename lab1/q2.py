# Function to encrypt using Vigenère Cipher
def vigenere_encrypt(text, key):
    key = key.upper()
    result = ""
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    text_as_int = [ord(i) for i in text.upper()]
    for i in range(len(text_as_int)):
        value = (text_as_int[i] + key_as_int[i % key_length]) % 26
        result += chr(value + 65)
    return result

# Function to decrypt using Vigenère Cipher
def vigenere_decrypt(ciphertext, key):
    key = key.upper()
    result = ""
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    ciphertext_as_int = [ord(i) for i in ciphertext.upper()]
    for i in range(len(ciphertext_as_int)):
        value = (ciphertext_as_int[i] - key_as_int[i % key_length]) % 26
        result += chr(value + 65)
    return result

# Function to encrypt using Autokey Cipher
def autokey_encrypt(text, key):
    key = key.upper() + text.upper()
    result = ""
    key_length = len(key)
    key_as_int = [ord(i) for i in key]
    text_as_int = [ord(i) for i in text.upper()]
    for i in range(len(text_as_int)):
        value = (text_as_int[i] + key_as_int[i]) % 26
        result += chr(value + 65)
    return result

# Function to decrypt using Autokey Cipher
def autokey_decrypt(ciphertext, key):
    key = key.upper()
    result = ""
    ciphertext_as_int = [ord(i) for i in ciphertext.upper()]
    key_as_int = [ord(i) for i in key]
    
    for i in range(len(ciphertext_as_int)):
        value = (ciphertext_as_int[i] - key_as_int[i]) % 26
        decrypted_char = chr(value + 65)
        result += decrypted_char
        key_as_int.append(ord(decrypted_char))  # Append decrypted char to key stream
    return result

# Main program
def main():
    message = input("Enter the message to encrypt (spaces will be ignored): ").replace(" ", "").upper()
    print("Choose a cipher:")
    print("a) Vigenère Cipher")
    print("b) Autokey Cipher")
    
    choice = input("Enter your choice (a/b): ").lower()
    
    if choice == 'a':
        key = input("Enter the key (for Vigenère Cipher): ").replace(" ", "").upper()
        encrypted = vigenere_encrypt(message, key)
        decrypted = vigenere_decrypt(encrypted, key)
    
    elif choice == 'b':
        key = input("Enter the key (for Autokey Cipher): ").replace(" ", "").upper()
        encrypted = autokey_encrypt(message, key)
        decrypted = autokey_decrypt(encrypted, key)
    
    else:
        print("Invalid choice!")
        return
    
    print("Encrypted message:", encrypted)
    print("Decrypted message:", decrypted)

# Run the program
main()
