from hashlib import sha1
from time import sleep
import binascii


block_size = 64
output_size = 20


def b_xor(b1, b2):
    return bytes(x ^ y for x, y in list(zip(b1, b2)))


# hmac_sha1 implementation from pseudocode https://en.wikipedia.org/wiki/HMAC
def hmac_sha1(key, msg):

    # Keys longer than blockSize are shortened by hashing them
    if len(key) > block_size:
        key = sha1(key).digest()

    # Keys shorter than blockSize are padded to blockSize by padding with zeros on the right
    if len(key) < block_size:
        key += b'\x00' * (block_size - len(key))  # Pad key with zeros to make it blockSize bytes long

    o_key_pad = b_xor(key, (b'\x5c' * block_size))  # Outer padded key
    i_key_pad = b_xor(key, (b'\x36' * block_size))  # Inner padded key

    # Return digest instead of bytes
    return binascii.hexlify(sha1(o_key_pad + sha1(i_key_pad + msg).digest()).digest())


# Insecure compare returns early on failure allowing for an attacker to determine which character caused the failure
def insecure_compare(key, msg, client_signature):
    server_signature = hmac_sha1(key, msg)
    print(server_signature)
    for i in range(len(server_signature)):
        if server_signature[i] != client_signature[i]:
            return False
        sleep(0.05)
    return True
