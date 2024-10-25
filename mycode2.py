import hashlib
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Cipher import PKCS1_OAEP
from sympy import mod_inverse
from random import randint, getrandbits

# RSA encryption/decryption
def rsa_generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def rsa_encrypt(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.encrypt(message.encode())

def rsa_decrypt(private_key, ciphertext):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    return cipher.decrypt(ciphertext).decode()

# ElGamal digital signature scheme
def elgamal_keygen(bit_size=256):
    p = nextprime(getrandbits(bit_size))
    g = randint(1, p - 1)
    x = randint(1, p - 1)
    h = pow(g, x, p)
    return p, g, h, x

def elgamal_sign(p, g, x, message_hash):
    k = randint(1, p - 1)
    r = pow(g, k, p)
    s = (message_hash + x * r) * mod_inverse(k, p - 1) % (p - 1)
    return r, s

def elgamal_verify(p, g, h, message_hash, r, s):
    v1 = pow(g, message_hash, p)
    v2 = (pow(h, r, p) * pow(r, s, p)) % p
    return v1 == v2

# Hashing using SHA512
def sha512_hash(data):
    hash_object = hashlib.sha512(data.encode())
    return int.from_bytes(hash_object.digest(), 'big')

# Message history
chat_history = []

# Message transmission between A and B
def send_message(sender, receiver, sender_private_key, receiver_public_key, elgamal_keys):
    message = input(f"Enter message to send from {sender} to {receiver}: ")
    message_hash = sha512_hash(message)
    
    # Encrypt message using RSA
    encrypted_message = rsa_encrypt(receiver_public_key, message)

    # Sign message hash using ElGamal
    p, g, h, x = elgamal_keys
    r, s = elgamal_sign(p, g, x, message_hash)

    # Store the encrypted message, signature, and timestamp
    chat_history.append({
        "sender": sender,
        "receiver": receiver,
        "encrypted_message": encrypted_message,
        "signature": (r, s),
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    })

    print(f"Message sent from {sender} to {receiver}.")

# Decrypt message for User B
def decrypt_message(private_key):
    if not chat_history:
        print("No messages to decrypt.")
        return

    for index, entry in enumerate(chat_history):
        print(f"Message {index + 1}:")
        print(f"Sender: {entry['sender']}, Receiver: {entry['receiver']}, Timestamp: {entry['timestamp']}")
    
    message_index = int(input("Enter the message number you want to decrypt: ")) - 1
    entry = chat_history[message_index]
    
    decrypted_message = rsa_decrypt(private_key, entry["encrypted_message"])
    print(f"Decrypted Message: {decrypted_message}")

# Verify the message integrity for Auditor (User C)
def verify_message(elgamal_keys):
    if not chat_history:
        print("No messages to verify.")
        return

    for index, entry in enumerate(chat_history):
        print(f"Message {index + 1}:")
        print(f"Sender: {entry['sender']}, Receiver: {entry['receiver']}, Timestamp: {entry['timestamp']}")

    message_index = int(input("Enter the message number you want to verify: ")) - 1
    entry = chat_history[message_index]
    
    # Prompt the auditor for the original message hash to verify integrity
    message = input("Enter the original message you believe was sent: ")
    original_message_hash = sha512_hash(message)

    r, s = entry["signature"]
    p, g, h, _ = elgamal_keys

    if elgamal_verify(p, g, h, original_message_hash, r, s):
        print("Message integrity is valid.")
    else:
        print("Message integrity is compromised!")

# View chat history for both A and B
def view_chat_history():
    if not chat_history:
        print("No messages in the chat history.")
        return
    
    for entry in chat_history:
        print(f"Sender: {entry['sender']}, Receiver: {entry['receiver']}, Timestamp: {entry['timestamp']}")

def main():
    # Generate RSA keys for A and B
    a_private_key, a_public_key = rsa_generate_keys()
    b_private_key, b_public_key = rsa_generate_keys()

    # Generate ElGamal keys for signing
    elgamal_keys = elgamal_keygen()

    while True:
        print("\n--- Secure Messaging System ---")
        print("1. A sends a message to B")
        print("2. B sends a message to A")
        print("3. A decrypts a message")
        print("4. B decrypts a message")
        print("5. Auditor C verifies a message")
        print("6. View chat history")
        print("7. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            send_message("A", "B", a_private_key, b_public_key, elgamal_keys)
        elif choice == '2':
            send_message("B", "A", b_private_key, a_public_key, elgamal_keys)
        elif choice == '3':
            decrypt_message(a_private_key)
        elif choice == '4':
            decrypt_message(b_private_key)
        elif choice == '5':
            verify_message(elgamal_keys)
        elif choice == '6':
            view_chat_history()
        elif choice == '7':
            print("Exiting the system.")
            break
        else:
            print("Invalid choice! Please select again.")

if __name__ == "__main__":
    main()
