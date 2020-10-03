# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/3/challenges/17
# The CBC padding oracle
#
# This is the best-known attack on modern block-cipher cryptography.
#
# Combine your padding code and your CBC code to write two functions.
#
# The first function should select at random one of the following 10 strings:
#
# MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
# MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
# MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
# MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
# MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
# MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
# MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
# MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
# MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
# MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

# ... generate a random AES key (which it should save for all future encryptions), pad the
# string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the
# caller the ciphertext and IV.
#
# The second function should consume the ciphertext produced by the first function, decrypt it,
# check its padding, and return true or false depending on whether the padding is valid.
#
# What you're doing here.
# This pair of functions approximates AES-CBC encryption as its deployed serverside in web
# applications; the second function models the server's consumption of an encrypted session
# token, as if it was a cookie.
#
# It turns out that it's possible to decrypt the ciphertexts provided by the first function.
#
# The decryption here depends on a side-channel leak by the decryption function. The leak is
# the error message that the padding is valid or not.
#
# You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll
# say is this:
#
# The fundamental insight behind this attack is that the byte 01h is valid padding, and occur
# in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.
#
# 02h in isolation is not valid padding.
#
# 02h 02h is valid padding, but is much less likely to occur randomly than 01h.
#
# 03h 03h 03h is even less likely.
#
# So you can assume that if you corrupt a decryption AND it had valid padding, you know what
# that padding byte is.
#
# It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles
# have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a
# specific bit of code that handles decryption. You can mount a padding oracle on any CBC
# block, whether it's padded or not.

import base64
from random import randint
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

block_length = 16
key = b'asjdhwuajskdja!s'


def cbc_encrypt(b64text, iv):
    plaintext = base64.b64decode(b64text)

    pad = padding.PKCS7(8 * block_length)
    aes = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

    padder = pad.padder()
    encryptor = aes.encryptor()

    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext


# This is the padding oracle. This function is the one that would have to
# be replaced in a real attack.
def is_valid_padding(ciphertext, iv):
    pad = padding.PKCS7(8 * block_length)
    aes = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

    unpadder = pad.unpadder()
    decryptor = aes.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

    try:
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    except ValueError:
        return False

    return True


def find_padding_bytes(ciphertext, iv, block_size):
    ciphertext = iv + ciphertext
    l = len(ciphertext)
    c_1 = ciphertext[:l - (2 * block_size)]
    c_2 = ciphertext[l - (2 * block_size):l - block_size]
    c_3 = ciphertext[l - block_size:]

    for i in range(block_size):
        mod = c_2[:i] + bytes([1 ^ c_2[i]]) + c_2[i + 1:]
        new = c_1 + mod + c_3
        if is_valid_padding(new[block_size:], new[:block_size]) is False:
            return block_size - i
    raise ValueError('Can\'t find padding bytes')


# This is the brute force part of the attack where each potential byte is
# iterated through for the first byte of padding. Whichever byte injected
# into the ciphertext resulting in a successful padding will be returned.
def brute_byte(attack_byte, x, y, z, block_size):
    for i in range(0, 256):
        if i is not attack_byte:
            mod_c = x + bytes([i]) + y + z
            if is_valid_padding(mod_c[block_size:], mod_c[:block_size]):
                return i

    return attack_byte


def solve_byte(c, index, block_size, original):
    # Prepend the iv because it will be needed to decrypt the last block
    # Record the variable that will be brute forced
    attack_byte = c[index]

    # current_pad is equal to the value of each padding byte of the ciphertext
    # If a block is 0d0d0d0d 0d0d0202 - then current_pad = 2
    # This is not confirmed but assumed because the calling function is
    # responsible for passing a valid padded ciphertext with the index
    # at the last byte before the padding begins. In the above example,
    # the index is assumed to be 5, since it is 0 based.
    # current_pad would be equal to:
    # 8 - (5 % 8) - 1
    # current_pad = 8 - 5 - 1
    # current_pad = 2
    # When the current padding is equivalent to the block size, the last block
    # is stripped off and a padding of \x01 will be matched
    current_pad = block_size - (index % block_size) - 1
    if current_pad is 0:
        cut = len(c) - 2 * block_size
        c = c[:cut]
        c += original[len(c):len(c) + block_size]

    # Each byte in the cipher, up until the one we are currently trying to decipher,
    # is saved. These bytes will not be modified this round. All the modified bytes
    # will be appended to these at the end to create the new ciphertext
    first_c = c[:index]

    # This will hold all of the bytes that have changed this round
    second_c = b''

    # This will be all of the bytes that come after the modified bytes.
    third_c = c[len(c) - block_size:]

    # This is where we modify each ciphertext byte that is currently responsible for
    # padding. if there were two \x02's then they become \x03's so the previous byte
    # can be brute forced to \x03. If current pad is 0, this will not execute because
    # it is not needed. The block is removed earlier and the attack is started anew
    # with \x01
    for x in range(1, block_size - (index % block_size)):
        second_c += bytes([(current_pad + 1) ^ c[index + x] ^ current_pad])

    # The byte of ciphertext that effects the first padding byte is bruteforced
    # Once this is obtained, the plaintext byte can be obtained
    found = brute_byte(attack_byte, first_c, second_c, third_c, block_size)

    return {
        'p': bytes([found ^ (current_pad + 1) ^ attack_byte]),
        'c': first_c + bytes([found]) + second_c + third_c
    }


def attack_cbc(ciphertext, iv, block_size):
    answer = b''
    original = iv + ciphertext
    p = bytearray(len(ciphertext))
    padding_bytes = find_padding_bytes(ciphertext, iv, block_size)
    p[len(p) - padding_bytes:] = bytes([padding_bytes]) * padding_bytes

    ciphertext = original
    reverse = b''
    for i in range(len(p) - padding_bytes - 1, -1, -1):
        result = solve_byte(ciphertext, i, block_size, original)
        ciphertext = result['c']
        reverse += result['p']
    swap_data = bytearray(reverse)
    swap_data.reverse()
    for i in swap_data:
        answer += bytes([i])
    return answer


def main():
    iv = urandom(block_length)
    with open('../resources/ch17.txt', 'rb') as my_file:
        lines = my_file.readlines()

    to_encrypt = lines[randint(0, len(lines) - 1)]

    ciphertext = cbc_encrypt(to_encrypt, iv)
    broken = attack_cbc(ciphertext, iv, 16)
    print(broken)


if __name__ == "__main__":
    main()
