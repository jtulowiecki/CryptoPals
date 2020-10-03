from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

block_length = 16
key = urandom(block_length)
iv = urandom(block_length)


def split_bytes(bytes, block_size):
	return [binascii.hexlify(bytes[i*block_size:(i+1)*block_size]) 
		for i in range(len(bytes)//block_size)]


def cbc_encrypt(text):

	filtered = b''
	for i in text:
		if (bytes([i]) != b';') and (bytes([i]) != b'='):
			filtered += bytes([i])

	prepend = b'comment1=cooking%20MCs;userdata='
	append = b';comment2=%20like%20a%20pound%20of%20bacon'

	plaintext = prepend + filtered + append

	pad = padding.PKCS7(8*block_length)
	aes = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

	padder = pad.padder()
	encryptor = aes.encryptor()

	padded_plaintext = padder.update(plaintext) + padder.finalize()
	ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
	
	return ciphertext


def cbc_decrypt(ciphertext):
	
	pad = padding.PKCS7(8*block_length)
	aes = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

	unpadder = pad.unpadder()
	decryptor = aes.decryptor()
	
	padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
	plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

	if b';admin=true;' in plaintext:
		return True
	return False

def byte_xor(ba1, ba2, ba3):
    first = bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])
    return bytes([_a ^ _b for _a, _b in zip(first, ba3)])

def main():
	
	c = cbc_encrypt(b'aaaaaxadminxtrue')
	c2 = c[:21]
	c2 += byte_xor(b'x', b';', bytes([c[21]]))
	c2 += c[22:27]
	c2 += byte_xor(b'x', b'=', bytes([c[27]]))
	c2 += c[28:]
	print(cbc_decrypt(c2))


if __name__ == "__main__":
	main()
	