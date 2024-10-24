import phe as paillier
from collections import defaultdict

# 2a: Create a dataset of documents
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

# 2b: Paillier Cryptosystem for Encryption/Decryption
# Generate public and private keys
public_key, private_key = paillier.generate_paillier_keypair()

# 2b: Encryption and Decryption functions using Paillier
def paillier_encrypt(public_key, value):
    return public_key.encrypt(value)

def paillier_decrypt(private_key, encrypted_value):
    return private_key.decrypt(encrypted_value)

# 2c: Create an inverted index
inverted_index = defaultdict(list)

# Build the inverted index (word -> [document IDs])
for doc_id, text in documents.items():
    for word in text.split():
        inverted_index[word].append(doc_id)

# Encrypt the index using Paillier cryptosystem
encrypted_inverted_index = {}
for word, doc_ids in inverted_index.items():
    encrypted_word = paillier_encrypt(public_key, sum([ord(char) for char in word]))  # Encrypt word as numeric representation
    encrypted_doc_ids = [paillier_encrypt(public_key, doc_id) for doc_id in doc_ids]  # Encrypt document IDs
    encrypted_inverted_index[encrypted_word] = encrypted_doc_ids

# 2d: Implement the search function
def search(query):
    # Encrypt the search query using the public key (convert query to sum of ASCII values)
    query_value = sum([ord(char) for char in query])
    encrypted_query = paillier_encrypt(public_key, query_value)

    # Search the encrypted index for matching terms
    matching_encrypted_docs = None
    for enc_word, enc_doc_ids in encrypted_inverted_index.items():
        # Compare encrypted values by decrypting both (since Paillier doesn't support direct equality check in encrypted form)
        if paillier_decrypt(private_key, enc_word) == query_value:
            matching_encrypted_docs = enc_doc_ids
            break

    if matching_encrypted_docs:
        # Decrypt the returned document IDs
        decrypted_doc_ids = [paillier_decrypt(private_key, enc_doc_id) for enc_doc_id in matching_encrypted_docs]

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
