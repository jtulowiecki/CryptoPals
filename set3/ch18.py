# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/3/challenges/18
# Implement CTR, the stream cipher mode
#
# The string:
#
# L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
# ... decrypts to something approximating English in CTR mode, which is an AES block
# cipher mode that turns AES into a stream cipher, with the following parameters:
#
#       key=YELLOW SUBMARINE
#       nonce=0
#       format=64 bit unsigned little endian nonce,
#              64 bit little endian block count (byte count / 16)
# CTR mode is very simple.
#
# Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing
# a 16 byte block of keystream, which is XOR'd against the plaintext.
#
# For instance, for the first 16 bytes of a message with these parameters:
#
# keystream = AES("YELLOW SUBMARINE",
#                 "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
# ... for the next 16 bytes:
#
# keystream = AES("YELLOW SUBMARINE",
#                 "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
# ... and then:
#
# keystream = AES("YELLOW SUBMARINE",
#                 "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
# CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing
# keystream and stop generating keystream.
#
# Decryption is identical to encryption. Generate the same keystream, XOR, and recover
# the plaintext.
#
# Decrypt the string at the top of this function, then use your CTR function to encrypt
# and decrypt other things.

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util import Counter
import base64


class Custom_CTR:

    def __init__(self, key):
        self.aes_custom = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

    def custom_aes_128_ctr_keystream_generator(self, nonce, counter):
        while True:
            to_encrypt = (nonce.to_bytes(length=8, byteorder='little')
                          + counter.to_bytes(length=8, byteorder='little'))
            encryptor = self.aes_custom.encryptor()
            keystream_block = encryptor.update(to_encrypt) + encryptor.finalize()
            yield from keystream_block
            counter += 1

    def custom_aes_128_ctr_encrypt(self, nonce, counter, data):
        result = b''
        my_gen = self.custom_aes_128_ctr_keystream_generator(nonce, counter)
        for i in range(len(data)):
            result += bytes([next(my_gen) ^ data[i]])
        return result


def pycrypto_aes_128_ctr_encrypt(key, data):
    _ctr = Counter.new(64, initial_value=0, prefix=b'\x00'*8, little_endian=True)
    aes = AES.new(key, AES.MODE_CTR, counter=_ctr)
    return aes.encrypt(data)


k = b'YELLOW SUBMARINE'
ctr = Custom_CTR(k)
enc = base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
print('custom ctr:', ctr.custom_aes_128_ctr_encrypt(0, 0, enc))
print('hazmat ctr:', pycrypto_aes_128_ctr_encrypt(k, enc))
