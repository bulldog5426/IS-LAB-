import random
import time

# Helper function to calculate modular inverse (used in both Paillier and ElGamal)
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

# Paillier Cryptosystem (Supports Homomorphic Addition)
class Paillier:
    def __init__(self, bit_length=512):
        self.bit_length = bit_length
        self.keygen()

    def keygen(self):
        p = self.generate_prime()
        q = self.generate_prime()
        self.n = p * q
        self.n_sq = self.n * self.n  # n^2
        self.g = self.n + 1  # Standard choice for g
        self.lambda_val = (p - 1) * (q - 1) // gcd(p - 1, q - 1)  # LCM of (p-1) and (q-1)
        self.mu = modinv(self.l_function(pow(self.g, self.lambda_val, self.n_sq)), self.n)

    def generate_prime(self):
        while True:
            prime_candidate = random.getrandbits(self.bit_length)
            if self.is_prime(prime_candidate):
                return prime_candidate

    def is_prime(self, n):
        if n % 2 == 0:
            return False
        for _ in range(5):
            a = random.randint(2, n - 2)
            if pow(a, n - 1, n) != 1:
                return False
        return True

    def l_function(self, x):
        return (x - 1) // self.n

    def encrypt(self, m):
        r = random.randint(1, self.n - 1)
        return (pow(self.g, m, self.n_sq) * pow(r, self.n, self.n_sq)) % self.n_sq

    def decrypt(self, c):
        return (self.l_function(pow(c, self.lambda_val, self.n_sq)) * self.mu) % self.n

# ElGamal Cryptosystem (Supports Homomorphic Multiplication)
class ElGamal:
    def __init__(self, bit_length=256):
        self.bit_length = bit_length
        self.keygen()

    def keygen(self):
        self.p = self.generate_prime()
        self.g = random.randint(2, self.p - 2)
        self.x = random.randint(1, self.p - 2)
        self.h = pow(self.g, self.x, self.p)

    def generate_prime(self):
        while True:
            prime_candidate = random.getrandbits(self.bit_length)
            if self.is_prime(prime_candidate):
                return prime_candidate

    def is_prime(self, n):
        if n % 2 == 0:
            return False
        for _ in range(5):
            a = random.randint(2, n - 2)
            if pow(a, n - 1, n) != 1:
                return False
        return True

    def encrypt(self, m):
        y = random.randint(1, self.p - 2)
        c1 = pow(self.g, y, self.p)
        s = pow(self.h, y, self.p)
        c2 = (m * s) % self.p
        return c1, c2

    def decrypt(self, c1, c2):
        s = pow(c1, self.x, self.p)
        s_inv = modinv(s, self.p)
        return (c2 * s_inv) % self.p

# Benchmarking function to compare Paillier and ElGamal
def benchmark_phe():
    print("Benchmarking Paillier encryption...")
    paillier = Paillier()
    m1, m2 = 1234, 5678

    start = time.time()
    c1 = paillier.encrypt(m1)
    c2 = paillier.encrypt(m2)
    end = time.time()
    print(f"Paillier encryption time: {end - start} seconds")

    start = time.time()
    c_add = (c1 * c2) % paillier.n_sq
    decrypted_sum = paillier.decrypt(c_add)
    end = time.time()
    print(f"Paillier homomorphic addition and decryption time: {end - start} seconds")
    print(f"Decrypted sum: {decrypted_sum} (should be {m1 + m2})")

    print("\nBenchmarking ElGamal encryption...")
    elgamal = ElGamal()

    start = time.time()
    c1_1, c2_1 = elgamal.encrypt(m1)
    c1_2, c2_2 = elgamal.encrypt(m2)
    end = time.time()
    print(f"ElGamal encryption time: {end - start} seconds")

    start = time.time()
    c1_mul = (c1_1 * c1_2) % elgamal.p
    c2_mul = (c2_1 * c2_2) % elgamal.p
    decrypted_product = elgamal.decrypt(c1_mul, c2_mul)
    end = time.time()
    print(f"ElGamal homomorphic multiplication and decryption time: {end - start} seconds")
    print(f"Decrypted product: {decrypted_product} (should be {m1 * m2})")

# Simulate secure data sharing using Paillier encryption
def paillier_data_sharing():
    paillier = Paillier()

    # Party 1
    data1 = int(input("Party 1: Enter your data (integer): "))
    encrypted_data1 = paillier.encrypt(data1)
    print(f"Party 1 encrypted data: {encrypted_data1}")

    # Party 2
    data2 = int(input("Party 2: Enter your data (integer): "))
    encrypted_data2 = paillier.encrypt(data2)
    print(f"Party 2 encrypted data: {encrypted_data2}")

    # Combine data (homomorphic addition)
    combined_encrypted_data = (encrypted_data1 * encrypted_data2) % paillier.n_sq
    print(f"Combined encrypted data: {combined_encrypted_data}")

    # Decrypt combined data
    combined_data = paillier.decrypt(combined_encrypted_data)
    print(f"Decrypted combined data: {combined_data}")
    print(f"Should be: {data1 + data2}")

# Simulate ElGamal homomorphic multiplication
def elgamal_demo():
    elgamal = ElGamal()

    # Take two integers
    m1 = int(input("Enter the first integer: "))
    m2 = int(input("Enter the second integer: "))

    # Encrypt the integers
    c1_1, c2_1 = elgamal.encrypt(m1)
    c1_2, c2_2 = elgamal.encrypt(m2)

    # Perform homomorphic multiplication
    c1_mul = (c1_1 * c1_2) % elgamal.p
    c2_mul = (c2_1 * c2_2) % elgamal.p
    print(f"Encrypted result of multiplication: (c1_mul: {c1_mul}, c2_mul: {c2_mul})")

    # Decrypt the result
    decrypted_product = elgamal.decrypt(c1_mul, c2_mul)
    print(f"Decrypted product: {decrypted_product}")
    print(f"Should be: {m1 * m2}")

# Main function to select a task
def main():
    print("Select a task to perform:")
    print("1: Benchmark Paillier and ElGamal")
    print("2: Simulate Secure Data Sharing with Paillier")
    print("3: Demonstrate Homomorphic Multiplication with ElGamal")
    choice = int(input("Enter your choice: "))

    if choice == 1:
        benchmark_phe()
    elif choice == 2:
        paillier_data_sharing()
    elif choice == 3:
        elgamal_demo()
    else:
        print("Invalid choice!")

if __name__ == "__main__":
    main()
