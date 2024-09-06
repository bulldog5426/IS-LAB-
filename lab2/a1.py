import time
from Crypto.Cipher import DES, AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad
import matplotlib.pyplot as plt

# Define the modes of operation
modes = {
    'ECB': AES.MODE_ECB,
    'CBC': AES.MODE_CBC,
    'CFB': AES.MODE_CFB,
    'OFB': AES.MODE_OFB
}

# Messages to encrypt
messages = [
    b"Message 1: This is a test.",
    b"Message 2: Performance matters.",
    b"Message 3: Security is essential.",
    b"Message 4: Encryption techniques vary.",
    b"Message 5: Always use strong keys."
]

# Common keys for DES and AES
des_key = get_random_bytes(8)  # DES key (8 bytes)
aes_key_128 = get_random_bytes(16)  # AES-128 key (16 bytes)
aes_key_192 = get_random_bytes(24)  # AES-192 key (24 bytes)
aes_key_256 = get_random_bytes(32)  # AES-256 key (32 bytes)

# Time tracking dictionaries
des_times = {mode: [] for mode in modes}
aes_128_times = {mode: [] for mode in modes}
aes_192_times = {mode: [] for mode in modes}
aes_256_times = {mode: [] for mode in modes}

# Encrypt messages using DES
def encrypt_des(mode, messages, key):
    times = []
    for msg in messages:
        cipher = DES.new(key, mode) if mode == DES.MODE_ECB else DES.new(key, mode, get_random_bytes(8))
        start_time = time.time()
        ciphertext = cipher.encrypt(pad(msg, DES.block_size))
        times.append(time.time() - start_time)
    return times

# Encrypt messages using AES
def encrypt_aes(mode, messages, key):
    times = []
    for msg in messages:
        cipher = AES.new(key, mode) if mode == AES.MODE_ECB else AES.new(key, mode, get_random_bytes(16))
        start_time = time.time()
        ciphertext = cipher.encrypt(pad(msg, AES.block_size))
        times.append(time.time() - start_time)
    return times

# Run DES encryption in different modes
for mode_name, mode in modes.items():
    des_times[mode_name] = encrypt_des(mode, messages, des_key)
    
# Run AES encryption in different modes with different key sizes
for mode_name, mode in modes.items():
    aes_128_times[mode_name] = encrypt_aes(mode, messages, aes_key_128)
    aes_192_times[mode_name] = encrypt_aes(mode, messages, aes_key_192)
    aes_256_times[mode_name] = encrypt_aes(mode, messages, aes_key_256)

# Average the times for plotting
def average_times(times_dict):
    return {mode: sum(times) / len(times) for mode, times in times_dict.items()}

des_avg_times = average_times(des_times)
aes_128_avg_times = average_times(aes_128_times)
aes_192_avg_times = average_times(aes_192_times)
aes_256_avg_times = average_times(aes_256_times)

# Plotting the graph for comparison
modes_list = list(modes.keys())
des_avg_list = [des_avg_times[mode] for mode in modes_list]
aes_128_avg_list = [aes_128_avg_times[mode] for mode in modes_list]
aes_192_avg_list = [aes_192_avg_times[mode] for mode in modes_list]
aes_256_avg_list = [aes_256_avg_times[mode] for mode in modes_list]

plt.figure(figsize=(10, 6))

plt.plot(modes_list, des_avg_list, label='DES', marker='o')
plt.plot(modes_list, aes_128_avg_list, label='AES-128', marker='o')
plt.plot(modes_list, aes_192_avg_list, label='AES-192', marker='o')
plt.plot(modes_list, aes_256_avg_list, label='AES-256', marker='o')

plt.title('Execution Time Comparison of DES and AES with Different Modes')
plt.xlabel('Modes of Operation')
plt.ylabel('Average Execution Time (seconds)')
plt.legend()
plt.grid(True)
plt.show()
