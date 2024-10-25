import random
import math

# Paillier Key Generation
def paillier_keygen(bits=512):
    p = random.getrandbits(bits // 2)
    q = random.getrandbits(bits // 2)
    n = p * q
    n_sq = n * n
    g = n + 1  # Set g to n + 1 to ensure the property holds.
    lambda_param = (p - 1) * (q - 1)
    mu = pow(lambda_param, -1, n)
    return (n, g), (lambda_param, mu)

# Paillier Encryption
def paillier_encrypt(public_key, plaintext):
    n, g = public_key
    r = random.randint(1, n - 1)
    c = (pow(g, plaintext, n * n) * pow(r, n, n * n)) % (n * n)
    return c

# Paillier Decryption
def paillier_decrypt(private_key, public_key, ciphertext):
    n, g = public_key
    lambda_param, mu = private_key
    n_sq = n * n
    u = pow(ciphertext, lambda_param, n_sq) - 1
    plaintext = ((u // n) * mu) % n
    return plaintext

# Homomorphic Addition of encrypted numbers
def paillier_homomorphic_addition(public_key, encrypted_numbers):
    n, g = public_key
    n_sq = n * n
    result = 1
    for c in encrypted_numbers:
        result = (result * c) % n_sq
    return result

# Main Function
def main():
    # Step 1: Key generation
    public_key, private_key = paillier_keygen()

    # Step 2: Input 'n' numbers from the user
    n = int(input("Enter the number of integers you want to add: "))
    numbers = []
    for i in range(n):
        num = int(input(f"Enter integer {i+1}: "))
        numbers.append(num)

    # Step 3: Encrypt each number
    encrypted_numbers = []
    for number in numbers:
        encrypted_num = paillier_encrypt(public_key, number)
        encrypted_numbers.append(encrypted_num)
        print(f"Encrypted {number} as: {encrypted_num}")

    # Step 4: Perform homomorphic addition
    encrypted_sum = paillier_homomorphic_addition(public_key, encrypted_numbers)
    print(f"Encrypted sum of the {n} numbers: {encrypted_sum}")

    # Step 5: Decrypt the result
    decrypted_sum = paillier_decrypt(private_key, public_key, encrypted_sum)
    print(f"Decrypted sum: {decrypted_sum}")

    # Step 6: Verify if the decrypted sum matches the original sum
    original_sum = sum(numbers)
    print(f"Original sum: {original_sum}")
    
    if decrypted_sum == original_sum:
        print("Success: Decrypted sum matches the original sum.")
    else:
        print("Error: Decrypted sum does not match the original sum.")

if __name__ == "__main__":
    main()
