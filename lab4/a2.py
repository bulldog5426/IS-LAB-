from sympy import isprime, factorint
import math

def generate_small_rsa_keys():
    # Example of small primes for demonstration purposes
    p = 61  # Small prime number
    q = 53  # Small prime number
    n = p * q
    e = 17  # Public exponent (commonly used value)
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)  # Compute the private exponent
    return (n, e), (n, d)

def rsa_encrypt(message, public_key):
    n, e = public_key
    message_int = int.from_bytes(message.encode(), byteorder='big')
    ciphertext = pow(message_int, e, n)
    return ciphertext

def rsa_decrypt(ciphertext, private_key):
    n, d = private_key
    decrypted_int = pow(ciphertext, d, n)
    message = decrypted_int.to_bytes((decrypted_int.bit_length() + 7) // 8, byteorder='big').decode()
    return message

def factorize_n(n):
    # Factorize n to find p and q
    factors = factorint(n)
    if len(factors) == 2:
        p, q = list(factors.keys())
        return p, q
    else:
        raise ValueError("The modulus does not factorize into exactly two primes.")

def recover_private_key(n, e, p, q):
    # Compute private key components
    phi_n = (p - 1) * (q - 1)
    d = pow(e, -1, phi_n)
    return (n, d)

def main():
    # Generate small RSA keys for demonstration
    public_key, private_key = generate_small_rsa_keys()
    n, e = public_key
    _, d = private_key

    print(f"Public Key: (n={n}, e={e})")
    print(f"Private Key: (n={n}, d={d})")

    # Encrypt and decrypt a message
    message = "Secure Data"
    ciphertext = rsa_encrypt(message, public_key)
    decrypted_message = rsa_decrypt(ciphertext, private_key)

    print(f"Original Message: {message}")
    print(f"Ciphertext: {ciphertext}")
    print(f"Decrypted Message: {decrypted_message}")

    # Eve's attack: Factorize n to recover p and q
    p, q = factorize_n(n)
    print(f"Factorized p and q: p={p}, q={q}")

    # Recover the private key
    recovered_private_key = recover_private_key(n, e, p, q)
    print(f"Recovered Private Key: (n={recovered_private_key[0]}, d={recovered_private_key[1]})")

    # Verify that the recovered private key works
    recovered_decrypted_message = rsa_decrypt(ciphertext, recovered_private_key)
    print(f"Recovered Decrypted Message: {recovered_decrypted_message}")

if __name__ == "__main__":
    main()
