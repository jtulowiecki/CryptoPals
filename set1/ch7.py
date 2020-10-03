# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/1/challenges/7
# AES in ECB mode
#
# The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key
#
# "YELLOW SUBMARINE".
# (case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).
#
# Decrypt it. You know the key, after all.

import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


def decrypt(ciphertext, key):
	decryptor = Cipher(algorithms.AES(key), modes.ECB(), default_backend()).decryptor()
	padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
	unpadder = padding.PKCS7(128).unpadder()
	unpadded_plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
	return unpadded_plaintext


def main():
	key = 'YELLOW SUBMARINE'.encode('utf-8')
	with open('../resources/ch7.txt', "rb") as my_file:
		b64encoded = my_file.read()
	ciphertext = base64.b64decode(b64encoded)
	print(decrypt(ciphertext, key).decode('ascii'))


if __name__ == "__main__":
	main()