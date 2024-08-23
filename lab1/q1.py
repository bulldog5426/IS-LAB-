# Function to encrypt using the Additive Cipher
def additive_encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            result += chr(((ord(char.upper()) - 65 + key) % 26) + 65)
    return result

# Function to decrypt using the Additive Cipher
def additive_decrypt(ciphertext, key):
    result = ""
    for char in ciphertext:
        if char.isalpha():
            result += chr(((ord(char.upper()) - 65 - key) % 26) + 65)
    return result

# Function to encrypt using the Multiplicative Cipher
def multiplicative_encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            result += chr(((ord(char.upper()) - 65) * key % 26) + 65)
    return result

# Function to decrypt using the Multiplicative Cipher
def multiplicative_decrypt(ciphertext, key):
    result = ""
    key_inv = mod_inverse(key, 26)
    if key_inv == -1:
        return "Invalid Key! No modular inverse exists."
    for char in ciphertext:
        if char.isalpha():
            result += chr(((ord(char.upper()) - 65) * key_inv % 26) + 65)
    return result

# Function to encrypt using the Affine Cipher
def affine_encrypt(text, key1, key2):
    result = ""
    for char in text:
        if char.isalpha():
            result += chr(((ord(char.upper()) - 65) * key1 + key2) % 26 + 65)
    return result

# Function to decrypt using the Affine Cipher
def affine_decrypt(ciphertext, key1, key2):
    result = ""
    key1_inv = mod_inverse(key1, 26)
    if key1_inv == -1:
        return "Invalid Key! No modular inverse exists."
    for char in ciphertext:
        if char.isalpha():
            result += chr((key1_inv * ((ord(char.upper()) - 65) - key2) % 26) + 65)
    return result

# Helper function to find the modular inverse (for multiplicative and affine cipher)
def mod_inverse(a, m):
    for i in range(1, m):
        if (a * i) % m == 1:
            return i
    return -1

# Main program
def main():
    message = input("Enter the message to encrypt (spaces will be ignored): ").replace(" ", "").upper()
    print("Choose a cipher:")
    print("a) Additive Cipher")
    print("b) Multiplicative Cipher")
    print("c) Affine Cipher")
    
    choice = input("Enter your choice (a/b/c): ").lower()
    
    if choice == 'a':
        key = int(input("Enter the key (integer) for Additive Cipher: "))
        encrypted = additive_encrypt(message, key)
        decrypted = additive_decrypt(encrypted, key)
    
    elif choice == 'b':
        key = int(input("Enter the key (integer) for Multiplicative Cipher: "))
        encrypted = multiplicative_encrypt(message, key)
        decrypted = multiplicative_decrypt(encrypted, key)
    
    elif choice == 'c':
        key1 = int(input("Enter the multiplicative key (integer) for Affine Cipher: "))
        key2 = int(input("Enter the additive key (integer) for Affine Cipher: "))
        encrypted = affine_encrypt(message, key1, key2)
        decrypted = affine_decrypt(encrypted, key1, key2)
    
    else:
        print("Invalid choice!")
        return
    
    print("Encrypted message:", encrypted)
    print("Decrypted message:", decrypted)

# Run the program
main()
