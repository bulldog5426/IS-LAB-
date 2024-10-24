# Import necessary modules
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA1, SHA256, SHA512, MD5
from sympy import mod_inverse, nextprime
from random import randint
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random.random import getrandbits
import hashlib

# 1. Symmetric Encryption

# DES (Data Encryption Standard)
def des_encrypt(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    padded_text = plaintext.ljust(8)
    return cipher.encrypt(padded_text.encode())

def des_decrypt(key, ciphertext):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(ciphertext).strip().decode()

# Example Usage:
# key = get_random_bytes(8)
# ciphertext = des_encrypt(key, "Hello")
# plaintext = des_decrypt(key, ciphertext)


# AES (Advanced Encryption Standard)
def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return cipher.iv + ct_bytes

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext[16:]), AES.block_size).decode()

# Example Usage:
# key = get_random_bytes(16)
# ciphertext = aes_encrypt(key, "Hello")
# plaintext = aes_decrypt(key, ciphertext)


# 2. Asymmetric Encryption

# RSA (Rivest–Shamir–Adleman)
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

# Example Usage:
# private_key, public_key = rsa_generate_keys()
# ciphertext = rsa_encrypt(public_key, "Hello")
# plaintext = rsa_decrypt(private_key, ciphertext)


# Rabin Cryptosystem
def rabin_keygen(bit_size=512):
    p, q = [nextprime(randint(2**(bit_size//2), 2**(bit_size//2+1))) for _ in range(2)]
    n = p * q
    return (p, q, n)

def rabin_encrypt(n, plaintext):
    m = int.from_bytes(plaintext.encode(), 'big')
    return pow(m, 2, n)

def rabin_decrypt(p, q, n, ciphertext):
    mp = pow(ciphertext, (p + 1) // 4, p)
    mq = pow(ciphertext, (q + 1) // 4, q)
    return (mp, mq)

# Example Usage:
# p, q, n = rabin_keygen()
# ciphertext = rabin_encrypt(n, "Hello")
# plaintext = rabin_decrypt(p, q, n, ciphertext)


# ElGamal Cryptosystem
def elgamal_keygen(bit_size=256):
    p = nextprime(getrandbits(bit_size))
    g = randint(1, p-1)
    x = randint(1, p-1)
    h = pow(g, x, p)
    return p, g, h, x

def elgamal_encrypt(p, g, h, message):
    y = randint(1, p-1)
    c1 = pow(g, y, p)
    m = int.from_bytes(message.encode(), 'big')
    c2 = (m * pow(h, y, p)) % p
    return c1, c2

def elgamal_decrypt(p, x, c1, c2):
    s = pow(c1, x, p)
    m = (c2 * mod_inverse(s, p)) % p
    return m.to_bytes((m.bit_length() + 7) // 8, 'big').decode()

# Example Usage:
# p, g, h, x = elgamal_keygen()
# c1, c2 = elgamal_encrypt(p, g, h, "Hello")
# plaintext = elgamal_decrypt(p, x, c1, c2)


# 3. Cryptographic Hash Functions

# SHA-1 (Secure Hash Algorithm 1)
def sha1_hash(data):
    hash_object = SHA1.new(data.encode())
    return hash_object.hexdigest()

# Example Usage:
# print(sha1_hash("Hello"))


# SHA-256 (Secure Hash Algorithm 256)
def sha256_hash(data):
    hash_object = SHA256.new(data.encode())
    return hash_object.hexdigest()

# Example Usage:
# print(sha256_hash("Hello"))


# SHA-512 (Secure Hash Algorithm 512)
def sha512_hash(data):
    hash_object = SHA512.new(data.encode())
    return hash_object.hexdigest()

# Example Usage:
# print(sha512_hash("Hello"))


# MD5 (Message Digest Algorithm 5)
def md5_hash(data):
    hash_object = MD5.new(data.encode())
    return hash_object.hexdigest()

# Example Usage:
# print(md5_hash("Hello"))


# 4. Key Exchange

# Diffie-Hellman Key Exchange
def diffie_hellman_key_exchange():
    p = nextprime(getrandbits(512))
    g = randint(2, p - 1)
    a = randint(1, p - 1)
    b = randint(1, p - 1)
    A = pow(g, a, p)
    B = pow(g, b, p)
    shared_secret_A = pow(B, a, p)
    shared_secret_B = pow(A, b, p)
    return shared_secret_A, shared_secret_B

# Example Usage:
# shared_secret_A, shared_secret_B = diffie_hellman_key_exchange()
# print(shared_secret_A == shared_secret_B)


# 5. Digital Signature Schemes

# Schnorr Signature Scheme
def schnorr_keygen(p, g):
    x = randint(1, p - 1)
    h = pow(g, x, p)
    return x, h

def schnorr_sign(p, g, x, message):
    k = randint(1, p - 1)
    r = pow(g, k, p)
    hash_value = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
    s = (k + x * hash_value) % (p - 1)
    return r, s

def schnorr_verify(p, g, h, message, r, s):
    hash_value = int.from_bytes(hashlib.sha256(message.encode()).digest(), 'big')
    v1 = pow(g, s, p)
    v2 = (r * pow(h, hash_value, p)) % p
    return v1 == v2

# Example Usage:
# p, g = 23, 5  # example small prime for simplicity
# x, h = schnorr_keygen(p, g)
# r, s = schnorr_sign(p, g, x, "Hello")
# valid = schnorr_verify(p, g, h, "Hello", r, s)
# print(valid)


# DSS (Digital Signature Standard)
def dss_sign(private_key, message):
    message_hash = SHA256.new(message.encode())
    signature = pkcs1_15.new(private_key).sign(message_hash)
    return signature

def dss_verify(public_key, message, signature):
    message_hash = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(message_hash, signature)
        return True
    except (ValueError, TypeError):
        return False

# Example Usage:
# private_key, public_key = rsa_generate_keys()
# signature = dss_sign(private_key, "Hello")
# valid = dss_verify(public_key, "Hello", signature)
# print(valid)
