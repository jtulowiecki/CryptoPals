# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/2/challenges/12
# Byte-at-a-time ECB decryption (Simple)
#
# Copy your oracle function to a new function that encrypts buffers under ECB mode using a
# consistent but unknown key (for instance, assign a single random key, once, to a global variable).
#
# Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following
# string:
#
# Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
# aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
# dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
# YnkK
# Spoiler alert.
# Do not decode this string now. Don't do it.
#
# Base64 decode the string before appending it. Do not base64 decode the string by hand; make
# your code do it. The point is that you don't know its contents.
#
# What you have now is a function that produces:
#
# AES-128-ECB(your-string || unknown-string, random-key)
# It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!
#
# Here's roughly how:
#
# 1 - Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"),
# then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do
# this step anyway.
#
# 2 - Detect that the function is using ECB. You already know, but do this step anyways.
#
# 3 - Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if
# the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to
# put in that last byte position.
#
# 4 - Make a dictionary of every possible last byte by feeding different strings to the oracle;
# for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
#
# 5 - Match the output of the one-byte-short input to one of the entries in your dictionary.
# You've now discovered the first byte of unknown-string.
#
# 6 - Repeat for the next byte.

from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
import base64

key = urandom(16)


# To break ECB, replace this with the encryption function you are trying to break
def ecb_encrypt(plaintext):
    b64_append = b'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'
    append_text = base64.b64decode(b64_append)
    plaintext += append_text

    pad = padding.PKCS7(8 * 16)
    aes = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

    padder = pad.padder()
    encryptor = aes.encryptor()

    padded_plaintext = padder.update(plaintext) + padder.finalize()
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


def detect_append_size():
    total_length = len(ecb_encrypt(b''))
    first = len(ecb_encrypt(b'A'))

    for i in range(2, 1000):
        result = ecb_encrypt(b'A' * i)
        if first != len(result):
            return total_length - i


def get_appended_text(block_size, append_length):
    found = b''
    counter = 0

    while len(found) < append_length:

        start_block = block_size * counter
        end_block = block_size * (counter + 1)

        for y in range((block_size - 1), -1, -1):

            one_short_out = ecb_encrypt(b'A' * y)[start_block:end_block]

            for i in range(256):
                x = bytes([i])
                test = ecb_encrypt(b'A' * y + found + x)[start_block:end_block]
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
    if not detect_ecb(block_size):
        print('Encryption function is not ECB!')
        return
    append_length = detect_append_size()
    result = get_appended_text(block_size, append_length)
    print(result)


if __name__ == "__main__":
    main()
