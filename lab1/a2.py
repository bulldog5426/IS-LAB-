def vigenere_encrypt(plaintext, keyword):
    # Remove spaces and convert to uppercase
    plaintext = plaintext.replace(" ", "").upper()
    keyword = keyword.upper()

    # Prepare the keyword to match the length of the plaintext
    keyword_repeated = (keyword * (len(plaintext) // len(keyword) + 1))[:len(plaintext)]

    ciphertext = ""
    
    for p_char, k_char in zip(plaintext, keyword_repeated):
        if p_char.isalpha():
            p_num = ord(p_char) - 65
            k_num = ord(k_char) - 65
            c_num = (p_num + k_num) % 26
            ciphertext += chr(c_num + 65)
        else:
            ciphertext += p_char
    
    return ciphertext

# Keyword and plaintext
keyword = "HEALTH"
plaintext = "Life is full of surprises"

# Encrypt the message
ciphertext = vigenere_encrypt(plaintext, keyword)
print("Ciphertext:", ciphertext)
