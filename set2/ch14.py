# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/2/challenges/14
# Byte-at-a-time ECB decryption (Harder)
#
# Take your oracle function from #12. Now generate a random count of random bytes and prepend this
# string to every plaintext. You are now doing:
#
# AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
# Same goal: decrypt the target-bytes.

from os import urandom
from random import randint
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

key = urandom(16)
prefix = urandom(randint(1, 15))


def split_bytes(bytes, block_size):
    return [bytes[i * block_size:(i + 1) * block_size] for i in range(len(bytes) // block_size)]


# To break ECB, replace this with the encryption function you are trying to break
def ecb_encrypt(plaintext):
    b64_append = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    append_text = base64.b64decode(b64_append)
    text = prefix + plaintext + append_text

    pad = padding.PKCS7(8 * 16)
    aes = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

    padder = pad.padder()
    encryptor = aes.encryptor()

    padded_plaintext = padder.update(text) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext


def eval_cipher(ciphertext, block_length):
    if len(ciphertext) % block_length != 0:
        raise ValueError

    blocks = [ciphertext[i:i + block_length] for i in range(0, len(ciphertext), block_length)]

    for i in range(len(blocks)):
        for x in range((i + 1), len(blocks)):
            if blocks[i] == blocks[x]:
                return True

    return False


def unpad_bytes(p):
    pad = padding.PKCS7(8 * 16)
    unpadder = pad.unpadder()
    return unpadder.update(p) + unpadder.finalize()


def detect_ecb(block_length):
    detection_text = b'A' * block_length * 3
    ciphertext = ecb_encrypt(detection_text)

    if eval_cipher(ciphertext, block_length):
        return True

    return False


def detect_block_size():
    first = len(ecb_encrypt(b'A'))

    for i in range(2, 1000):
        result = ecb_encrypt(b'A' * i)
        if first != len(result):
            return len(result) - first


# Returns -1 if no consecutive repeat blocks
# Returns the index of the first block in the repeat sequence for
# first repeat found
# This function does not account for multiple repeats
def has_repeat_blocks(ciphertext, block_size):
    split_c = split_bytes(ciphertext, block_size)
    for i in range(len(split_c) - 1):
        if split_c[i] == split_c[i + 1]:
            return i
    return -1


def detect_prepend_size(block_size):
    for i in range(block_size * 2, block_size * 3):
        repeats = has_repeat_blocks(ecb_encrypt(b'A' * i), block_size)
        if repeats >= 0:
            return (repeats * block_size) - (i - block_size * 2)


def detect_append_size(prepend_length):
    total_length = len(ecb_encrypt(b'')) - prepend_length
    first = len(ecb_encrypt(b'A')) - prepend_length

    for i in range(2, 1000):
        result = ecb_encrypt(b'A' * i)
        if first != (len(result) - prepend_length):
            return (total_length - i)


def get_appended_text(block_size, prepend_length, append_length):
    found = b''
    counter = 0

    # Make this an even block size
    prefix = b'A' * (block_size - (prepend_length % block_size))
    prepend_length = len(prefix) + prepend_length

    while (len(found) < append_length):

        start_block = block_size * counter + prepend_length
        end_block = block_size * (counter + 1) + prepend_length

        for y in range((block_size - 1), -1, -1):

            one_short_out = ecb_encrypt(prefix + b'A' * y)[start_block:end_block]

            for i in range(256):
                x = bytes([i])
                test = ecb_encrypt(prefix + b'A' * y + found + x)[start_block:end_block]
                if test == one_short_out:
                    found += x
                    break

        counter = counter + 1

    # This unpads the last block. The found string will not be padded correctly if the whole
    # string is taken. The last block is then appended to the prefix after the padding has
    # been removed
    prefix = found[:len(found) - block_size]
    suffix = found[len(found) - block_size:]
    unpadded_suffix = unpad_bytes(suffix)
    result = prefix + unpadded_suffix

    return result


def main():
    block_size = detect_block_size()
    if detect_ecb(block_size) == False:
        print('Encryption function is not ECB!')
        return
    prepend_length = detect_prepend_size(block_size)
    append_length = detect_append_size(prepend_length)
    result = get_appended_text(block_size, prepend_length, append_length)
    print(result)


if __name__ == "__main__":
    main()
