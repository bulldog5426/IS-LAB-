import random
from math import gcd

# Helper function to calculate modular inverse
def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m
        m, a = a % m, m
        x0, x1 = x1 - q * x0, x0
    if x1 < 0:
        x1 += m0
    return x1

# Paillier Encryption Scheme
class Paillier:
    def __init__(self, bit_length=512):
        self.bit_length = bit_length
        self.keygen()

    # Key generation
    def keygen(self):
        # Generate two large prime numbers p and q
        self.p = self.generate_prime()
        self.q = self.generate_prime()
        self.n = self.p * self.q  # n = p * q
        self.n_sq = self.n * self.n  # n^2
        self.lambda_ = (self.p - 1) * (self.q - 1) // gcd(self.p - 1, self.q - 1)
        self.g = self.n + 1  # g = n + 1 for Paillier cryptosystem
        self.mu = modinv(self.lambda_, self.n)  # Precompute mu = (L(g^λ mod n²))⁻¹ mod n

    # Generate a random prime number
    def generate_prime(self):
        while True:
            prime_candidate = random.getrandbits(self.bit_length)
            if self.is_prime(prime_candidate):
                return prime_candidate

    # Primality test
    def is_prime(self, n):
        if n % 2 == 0:
            return False
        for _ in range(5):  # Miller-Rabin test rounds
            a = random.randint(2, n - 2)
            if pow(a, n - 1, n) != 1:
                return False
        return True

    # Encryption
    def encrypt(self, m):
        r = random.randint(1, self.n - 1)
        while gcd(r, self.n) != 1:  # Ensure r is coprime with n
            r = random.randint(1, self.n - 1)
        c = (pow(self.g, m, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq
        return c

    # Decryption
    def decrypt(self, c):
        x = pow(c, self.lambda_, self.n_sq) - 1
        m = ((x // self.n) * self.mu) % self.n
        return m

# Main function to demonstrate Paillier encryption and homomorphic addition
def main():
    # Initialize Paillier encryption scheme
    paillier = Paillier()

    # Take two integer inputs from the user
    m1 = int(input("Enter the first integer: "))
    m2 = int(input("Enter the second integer: "))

    # Encrypt the two integers
    c1 = paillier.encrypt(m1)
    c2 = paillier.encrypt(m2)

    # Print the ciphertexts
    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}")

    # Perform homomorphic addition: E(m1) * E(m2) mod n^2
    c_add = (c1 * c2) % paillier.n_sq
    print(f"Encrypted result of addition: {c_add}")

    # Decrypt the result of the addition
    decrypted_sum = paillier.decrypt(c_add)
    print(f"Decrypted result of the addition: {decrypted_sum}")

    # Verify if decrypted sum matches the sum of the original integers
    assert decrypted_sum == (m1 + m2), "Homomorphic addition failed!"
    print("Homomorphic addition successful!")

if __name__ == "__main__":
    main()
