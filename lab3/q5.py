import time
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Generate Diffie-Hellman parameters
def generate_dh_parameters():
    parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())
    return parameters

# Generate a Diffie-Hellman key pair
def generate_dh_key_pair(parameters):
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

# Exchange keys and compute shared secret
def compute_shared_secret(private_key, peer_public_key):
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

# Measure Diffie-Hellman key exchange performance
def measure_dh_performance():
    # Generate parameters
    start_time = time.time()
    parameters = generate_dh_parameters()
    param_gen_time = time.time() - start_time
    
    # Generate key pairs for Peer 1 and Peer 2
    start_time = time.time()
    peer1_private_key, peer1_public_key = generate_dh_key_pair(parameters)
    peer2_private_key, peer2_public_key = generate_dh_key_pair(parameters)
    key_gen_time = time.time() - start_time
    
    # Exchange keys and compute shared secrets
    start_time = time.time()
    peer1_shared_secret = compute_shared_secret(peer1_private_key, peer2_public_key)
    peer2_shared_secret = compute_shared_secret(peer2_private_key, peer1_public_key)
    key_exchange_time = time.time() - start_time
    
    # Convert shared secrets to a consistent format for comparison
    peer1_shared_secret_hex = peer1_shared_secret.hex()
    peer2_shared_secret_hex = peer2_shared_secret.hex()
    
    return {
        "param_gen_time": param_gen_time,
        "key_gen_time": key_gen_time,
        "key_exchange_time": key_exchange_time,
        "peer1_shared_secret": peer1_shared_secret_hex,
        "peer2_shared_secret": peer2_shared_secret_hex
    }

# Print results
def print_results(results):
    print(f"Parameter Generation Time: {results['param_gen_time']:.2f} seconds")
    print(f"Key Generation Time: {results['key_gen_time']:.2f} seconds")
    print(f"Key Exchange Time: {results['key_exchange_time']:.2f} seconds")
    print(f"Peer 1 Shared Secret: {results['peer1_shared_secret']}")
    print(f"Peer 2 Shared Secret: {results['peer2_shared_secret']}")

if __name__ == "__main__":
    results = measure_dh_performance()
    print_results(results)
