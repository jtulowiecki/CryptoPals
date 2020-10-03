import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

class AES:

	def __init__(self, block_length, k):
		self.block_length = block_length
		self.aes_cipher = Cipher(algorithms.AES(k), modes.ECB(), default_backend())
		self.pad = padding.PKCS7(8*block_length)

	def ecb_encrypt_block(self, block):
		encryptor = self.aes_cipher.encryptor()
		return encryptor.update(block) + encryptor.finalize()

	def ecb_decrypt_block(self, block):
		decryptor = self.aes_cipher.decryptor()
		return decryptor.update(block) + decryptor.finalize()

	def cbc_encrypt(self, p, iv):
		c = b''
		padded = self.pad_bytes(p)
		last_c = iv
		for i in range(len(padded) // self.block_length):
			current_p = padded[i* self.block_length:(i+1)*self.block_length]
			last_c = self.ecb_encrypt_block(self.xor_bytes(last_c, current_p))
			c += last_c
		return c

	def cbc_decrypt(self, c, iv):
		p = b''
		
		last_c = iv
		for i in range(len(c) // self.block_length):
			current_c = c[i* self.block_length:(i+1)*self.block_length]
			current_p = self.xor_bytes(self.ecb_decrypt_block(current_c), last_c)
			last_c = current_c
			p += current_p
		return self.unpad_bytes(p)

	def pad_bytes(self, p):
		padder = self.pad.padder()
		return padder.update(p) + padder.finalize()

	def unpad_bytes(self, p):
		unpadder = self.pad.unpadder()
		return unpadder.update(p) + unpadder.finalize()

	def xor_bytes(self, a, b) :
		return bytes(x ^ y for x, y in list(zip(a, b)))

# Read and Base64 decode the ciphertext
with open('../resources/ch10.txt', "rb") as my_file:
	b64encoded = my_file.read()
c = base64.b64decode(b64encoded)

# Decrypt and print result
aes_crypt = AES(16, 'YELLOW SUBMARINE'.encode('utf-8'))
iv = b'\x00'*16
print(aes_crypt.cbc_decrypt(c, iv))