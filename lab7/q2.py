import random
from math import gcd

# Helper function to calculate the modular inverse
# This uses the Extended Euclidean Algorithm to find 'x' such that (a * x) % m == 1
def modinv(a, m):
    m0, x0, x1 = m, 0, 1
    if m == 1:
        return 0
    while a > 1:
        q = a // m  # Quotient
        m, a = a % m, m  # Update m and a using the remainder
        x0, x1 = x1 - q * x0, x0  # Update x0 and x1
    if x1 < 0:
        x1 += m0  # Make sure x1 is positive
    return x1

# RSA Encryption Scheme
class RSA:
    def __init__(self, bit_length=512):
        self.bit_length = bit_length  # Size of the prime numbers
        self.keygen()  # Generate public and private keys

    # Key generation function
    def keygen(self):
        # Step 1: Generate two large prime numbers p and q
        self.p = self.generate_prime()
        self.q = self.generate_prime()

        # Step 2: Compute n = p * q
        self.n = self.p * self.q

        # Step 3: Compute φ(n) = (p - 1) * (q - 1)
        self.phi = (self.p - 1) * (self.q - 1)

        # Step 4: Choose e such that 1 < e < φ(n) and gcd(e, φ(n)) = 1 (i.e., e is coprime with φ(n))
        self.e = self.choose_e(self.phi)

        # Step 5: Compute d, the modular inverse of e mod φ(n), i.e., d * e ≡ 1 (mod φ(n))
        self.d = modinv(self.e, self.phi)

    # Generate a random prime number of bit length 'bit_length'
    def generate_prime(self):
        while True:
            prime_candidate = random.getrandbits(self.bit_length)  # Generate a random number of the given bit length
            if self.is_prime(prime_candidate):  # Check if the number is prime
                return prime_candidate

    # Primality test using the Miller-Rabin algorithm
    def is_prime(self, n):
        if n % 2 == 0:  # If n is even, it's not prime
            return False
        for _ in range(5):  # Perform 5 rounds of the Miller-Rabin test
            a = random.randint(2, n - 2)  # Random number between 2 and n-2
            if pow(a, n - 1, n) != 1:  # Fermat's little theorem
                return False
        return True

    # Function to choose e such that gcd(e, φ(n)) = 1
    def choose_e(self, phi):
        e = random.randrange(1, phi)  # Pick a random number e between 1 and φ(n)
        while gcd(e, phi) != 1:  # Ensure that gcd(e, φ(n)) = 1 (i.e., e is coprime with φ(n))
            e = random.randrange(1, phi)
        return e

    # Encryption function: c = (m^e) % n
    def encrypt(self, m):
        return pow(m, self.e, self.n)

    # Decryption function: m = (c^d) % n
    def decrypt(self, c):
        return pow(c, self.d, self.n)

# Main function to demonstrate RSA encryption and homomorphic multiplication
def main():
    # Initialize the RSA encryption scheme
    rsa = RSA()

    # Take two integer inputs from the user
    m1 = int(input("Enter the first integer: "))
    m2 = int(input("Enter the second integer: "))

    # Step 1: Encrypt the two integers
    c1 = rsa.encrypt(m1)  # Ciphertext of the first integer
    c2 = rsa.encrypt(m2)  # Ciphertext of the second integer

    # Print the ciphertexts
    print(f"Ciphertext of {m1}: {c1}")
    print(f"Ciphertext of {m2}: {c2}")

    # Step 2: Perform homomorphic multiplication on the encrypted integers
    # E(m1) * E(m2) % n => This is equivalent to encrypting (m1 * m2) under the RSA scheme
    c_mul = (c1 * c2) % rsa.n
    print(f"Encrypted result of multiplication: {c_mul}")

    # Step 3: Decrypt the result of the multiplication
    decrypted_product = rsa.decrypt(c_mul)  # Decrypt the product
    print(f"Decrypted result of the multiplication: {decrypted_product}")

    # Step 4: Verify if decrypted product matches the product of the original integers
    assert decrypted_product == (m1 * m2), "Homomorphic multiplication failed!"  # Ensure the result is correct
    print("Homomorphic multiplication successful!")  # If successful, print confirmation

if __name__ == "__main__":
    main()
