import os
import random
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from collections import defaultdict

# Helper functions for padding
def pad(text):
    block_size = AES.block_size
    padding_len = block_size - len(text) % block_size
    padding = chr(padding_len) * padding_len
    return text + padding

def unpad(text):
    padding_len = ord(text[-1])
    return text[:-padding_len]

# 1b: Encryption and Decryption using AES
def aes_encrypt(key, plaintext):
    plaintext = pad(plaintext)
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(plaintext.encode())
    return b64encode(iv + ciphertext).decode('utf-8')

def aes_decrypt(key, ciphertext):
    ciphertext = b64decode(ciphertext)
    iv = ciphertext[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext[AES.block_size:]).decode('utf-8'))
    return plaintext

# 1a: Create a dataset of documents
documents = {
    1: "the quick brown fox",
    2: "jumped over the lazy dog",
    3: "hello world",
    4: "the fox is quick",
    5: "the dog is lazy",
    6: "hello from the other side",
    7: "world of quick animals",
    8: "lazy fox jumped",
    9: "hello quick brown fox",
    10: "dog jumped over"
}

# AES key for encryption
key = get_random_bytes(16)  # 16 bytes = 128 bits key

# 1c: Create an inverted index
inverted_index = defaultdict(list)

# Build the index
for doc_id, text in documents.items():
    for word in text.split():
        inverted_index[word].append(doc_id)

# Encrypt the index
encrypted_inverted_index = {}
for word, doc_ids in inverted_index.items():
    encrypted_word = aes_encrypt(key, word)  # Encrypt each word in the index
    encrypted_doc_ids = [aes_encrypt(key, str(doc_id)) for doc_id in doc_ids]  # Encrypt document IDs
    encrypted_inverted_index[encrypted_word] = encrypted_doc_ids

# 1d: Implement the search function
def search(query):
    # Encrypt the search query
    encrypted_query = aes_encrypt(key, query)

    # Search the encrypted inverted index for matching terms
    if encrypted_query in encrypted_inverted_index:
        encrypted_doc_ids = encrypted_inverted_index[encrypted_query]

        # Decrypt the returned document IDs
        decrypted_doc_ids = [int(aes_decrypt(key, enc_doc_id)) for enc_doc_id in encrypted_doc_ids]

        # Display the corresponding documents
        result_docs = {doc_id: documents[doc_id] for doc_id in decrypted_doc_ids}
        return result_docs
    else:
        return "No results found."

# Example Usage
if __name__ == "__main__":
    print("Documents in the corpus:")
    for doc_id, text in documents.items():
        print(f"Doc {doc_id}: {text}")

    # Input search query
    query = input("\nEnter search query: ").lower()

    # Perform the search on the encrypted index
    results = search(query)

    # Output the results
    if isinstance(results, dict):
        print("\nSearch Results:")
        for doc_id, text in results.items():
            print(f"Doc {doc_id}: {text}")
    else:
        print(results)
