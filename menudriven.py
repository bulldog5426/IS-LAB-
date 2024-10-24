import time
import hashlib
import json
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA512
from Crypto.Signature import DSS
from Crypto.PublicKey import ElGamal
from Crypto.Random.random import randint

# Global chat history
chat_history = []

# ElGamal key generation for signing
def generate_elgamal_keypair():
    elg_key = ElGamal.generate(2048, get_random_bytes)
    return elg_key

# RSA key generation for encryption
def generate_rsa_keypair():
    rsa_key = RSA.generate(2048)
    return rsa_key

# Message encryption using RSA
def rsa_encrypt(public_key, message):
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

# Message decryption using RSA
def rsa_decrypt(private_key, encrypted_message):
    cipher = PKCS1_OAEP.new(private_key)
    decrypted_message = cipher.decrypt(encrypted_message).decode()
    return decrypted_message

# Hashing the message using SHA512
def hash_message(message):
    hashed_message = SHA512.new(message.encode())
    return hashed_message

# Signing the hash with ElGamal
def elgamal_sign(private_key, hashed_message):
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hashed_message)
    return signature

# Verifying the signature with ElGamal
def elgamal_verify(public_key, hashed_message, signature):
    verifier = DSS.new(public_key, 'fips-186-3')
    try:
        verifier.verify(hashed_message, signature)
        return True
    except ValueError:
        return False

# Store messages with timestamp
def store_message(sender, receiver, encrypted_message, signature, timestamp):
    chat_history.append({
        "sender": sender,
        "receiver": receiver,
        "message": encrypted_message.hex(),
        "signature": signature.hex(),
        "timestamp": timestamp
    })

# Display chat history
def display_chat_history():
    if not chat_history:
        print("No chat history.")
    else:
        for chat in chat_history:
            print(f"Timestamp: {chat['timestamp']}")
            print(f"From: {chat['sender']} to {chat['receiver']}")
            print(f"Encrypted Message: {chat['message']}")
            print(f"Signature: {chat['signature']}")
            print('-' * 50)

# Simulate message sending between users
def send_message(sender, receiver, sender_rsa_keypair, receiver_rsa_public, sender_elg_keypair):
    message = input(f"{sender}, enter your message to {receiver}: ")
    
    # Encrypt the message with the receiver's RSA public key
    encrypted_message = rsa_encrypt(receiver_rsa_public, message)
    
    # Hash the message using SHA512
    hashed_message = hash_message(message)
    
    # Sign the hash with ElGamal private key
    signature = elgamal_sign(sender_elg_keypair, hashed_message)
    
    # Timestamp for the message
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime())
    
    # Store the message and signature in chat history
    store_message(sender, receiver, encrypted_message, signature, timestamp)
    
    print(f"Message sent from {sender} to {receiver}.")
    
# Simulate message receiving between users
def receive_message(receiver, receiver_rsa_keypair, sender_elg_public):
    if not chat_history:
        print(f"No messages for {receiver} to decrypt.")
        return
    
    # Find the latest message for the receiver
    for chat in reversed(chat_history):
        if chat['receiver'] == receiver:
            encrypted_message = bytes.fromhex(chat['message'])
            signature = bytes.fromhex(chat['signature'])
            
            # Decrypt the message
            decrypted_message = rsa_decrypt(receiver_rsa_keypair, encrypted_message)
            
            # Hash the decrypted message
            hashed_message = hash_message(decrypted_message)
            
            # Verify the signature
            if elgamal_verify(sender_elg_public, hashed_message, signature):
                print(f"Verified message from {chat['sender']}: {decrypted_message}")
                print(f"Timestamp: {chat['timestamp']}")
            else:
                print("Failed to verify the message's signature.")
            break
    else:
        print(f"No new messages for {receiver}.")

# Main menu
def main():
    # Generate RSA and ElGamal keys for both users
    rsa_keypair_a = generate_rsa_keypair()
    rsa_keypair_b = generate_rsa_keypair()
    
    elg_keypair_a = generate_elgamal_keypair()
    elg_keypair_b = generate_elgamal_keypair()
    
    while True:
        print("\nMenu:")
        print("1. User A sends a message to User B")
        print("2. User B sends a message to User A")
        print("3. User A views their messages")
        print("4. User B views their messages")
        print("5. Display chat history")
        print("6. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            send_message("A", "B", rsa_keypair_a, rsa_keypair_b.publickey(), elg_keypair_a)
        elif choice == "2":
            send_message("B", "A", rsa_keypair_b, rsa_keypair_a.publickey(), elg_keypair_b)
        elif choice == "3":
            receive_message("A", rsa_keypair_a, elg_keypair_b.publickey())
        elif choice == "4":
            receive_message("B", rsa_keypair_b, elg_keypair_a.publickey())
        elif choice == "5":
            display_chat_history()
        elif choice == "6":
            break
        else:
            print("Invalid choice! Please try again.")

# Start the program
if __name__ == "__main__":
    main()
