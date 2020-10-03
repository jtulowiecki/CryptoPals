# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/2/challenges/13
# ECB cut-and-paste
#
# Write a k=v parsing routine, as if for a structured cookie. The routine should take:
#
# foo=bar&baz=qux&zap=zazzle
# ... and produce:
#
# {
#   foo: 'bar',
#   baz: 'qux',
#   zap: 'zazzle'
# }
# (you know, the object; I don't care if you convert it to JSON).
#
# Now write a function that encodes a user profile in that format, given an email address.
# You should have something like:
#
# profile_for("foo@bar.com")
# ... and it should produce:
#
# {
#   email: 'foo@bar.com',
#   uid: 10,
#   role: 'user'
# }
# ... encoded as:
#
# email=foo@bar.com&uid=10&role=user
# Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them,
# quote them, whatever you want to do, but don't let people set their email address to
# "foo@bar.com&role=admin".
#
# Now, two more easy functions. Generate a random AES key, then:
#
# Encrypt the encoded user profile under the key; "provide" that to the "attacker".
# Decrypt the encoded user profile and parse it.
# Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts)
# and the ciphertexts themselves, make a role=admin profile.

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
