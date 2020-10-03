from os import urandom
import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

key = b'sjduwjdhaiwkd98d'

def ecb_encrypt(plaintext):

	pad = padding.PKCS7(8*16)
	aes = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

	padder = pad.padder()
	encryptor = aes.encryptor()

	padded_plaintext = padder.update(plaintext) + padder.finalize()
	ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

	return ciphertext


def ecb_decrypt(ciphertext):

	pad = padding.PKCS7(8*16)
	aes = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

	unpadder = pad.unpadder()
	decryptor = aes.decryptor()

	plaintext = decryptor.update(ciphertext) + decryptor.finalize()
	unpadded_plaintext = unpadder.update(plaintext) + unpadder.finalize()

	return unpadded_plaintext


def profile_for(email):
	if (b'&' or b'=') in email:
		raise ValueError

	profile = b'email=' + email + b'&uid=10&role=user'
	return ecb_encrypt(profile)


def main():
	email = b'aaaaaaaaaaaas'
	first_two_blocks = profile_for(email)[:32]

	email = b'aaaaaaaaaaadmin' + b'\x0b'*11
	third_block = profile_for(email)[16:32]

	result = first_two_blocks + third_block

	print(ecb_decrypt(result))

if __name__ == "__main__":
	main()