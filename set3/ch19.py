# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/3/challenges/19
# Break fixed-nonce CTR mode using substitutions
#
# Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a random AES key.
#
# In successive encryptions (not in one big running CTR stream), encrypt each line of the base64 decodes of the following, producing multiple independent ciphertexts:
#
# SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
# Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
# RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
# RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
# SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
# T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
# T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
# UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
# QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
# T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
# VG8gcGxlYXNlIGEgY29tcGFuaW9u
# QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
# QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
# QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
# QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
# QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
# VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
# SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
# SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
# VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
# V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
# V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
# U2hlIHJvZGUgdG8gaGFycmllcnM/
# VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
# QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
# VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
# V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
# SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
# U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
# U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
# VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
# QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
# SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
# VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
# WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
# SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
# SW4gdGhlIGNhc3VhbCBjb21lZHk7
# SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
# VHJhbnNmb3JtZWQgdXR0ZXJseTo=
# QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
# (This should produce 40 short CTR-encrypted ciphertexts).
#
# Because the CTR nonce wasn't randomized for each encryption, each ciphertext has been
# encrypted against the same keystream. This is very bad.
#
# Understanding that, like most stream ciphers (including RC4, and obviously any block
# cipher run in CTR mode), the actual "encryption" of a byte of data boils down to a
# single XOR operation, it should be plain that:
#
# CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
# And since the keystream is the same for every ciphertext:
#
# CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
# say!")
# Attack this cryptosystem piecemeal: guess letters, use expected English language
# frequence to validate guesses, catch common English trigrams, and so on.

from Crypto.Cipher import AES
from Crypto.Util import Counter
from os import urandom
import base64

"""
This is actually the exact same as ch20. I misinterpreted the challenge when it said to automate. I automated
using repeat key xor, and thats what ch20 is aboout.
"""


def pycrypto_aes_128_ctr_encrypt(key, data):
    _ctr = Counter.new(64, initial_value=0, prefix=b'\x00' * 8, little_endian=True)
    aes = AES.new(key, AES.MODE_CTR, counter=_ctr)
    return aes.encrypt(data)


def generate_ciphers():
    k = urandom(16)
    with open('../resources/ch19.txt', 'rb') as my_file:
        lines = my_file.readlines()
    with open('../resources/ch19_2.txt', 'w') as cipher_file:
        first = True
        for line in lines:
            if first:
                encrypted = pycrypto_aes_128_ctr_encrypt(k, base64.b64decode(line))
                cipher_file.write(base64.b64encode(encrypted).decode('ascii'))
                first = False
            else:
                cipher_file.write('\n')
                encrypted = pycrypto_aes_128_ctr_encrypt(k, base64.b64decode(line))
                cipher_file.write(base64.b64encode(encrypted).decode('ascii'))


def get_english_score(input_bytes):
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])


def single_char_xor(input_bytes, char_value):
    output_bytes = b''
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_value])
    return output_bytes


def getData(ciphertext, key):
    message = single_char_xor(ciphertext, key)
    score = get_english_score(message)
    data = {
        'ciphertext': ciphertext,
        'message': message,
        'score': score,
        'key': key
    }
    return data


def getBestScoreForLine(line):
    return max([getData(line, k) for k in range(256)], key=lambda x: x['score'])


def main():
    # generate_ciphers()
    key = b''
    data = []
    result = []
    with open('../resources/ch19_2.txt', 'rb') as my_file:
        lines = my_file.readlines()
    for line in lines:
        data.append(base64.b64decode(line))

    for i in range(100):
        key += bytes([getBestScoreForLine(bytes([data[x][i] for x in range(len(data)) if i < len(data[x])]))['key']])

    for c in data:
        result.append((bytes(x ^ y for x, y in list(zip(key, c[:100])))))
    print(result)


if __name__ == "__main__":
    main()
