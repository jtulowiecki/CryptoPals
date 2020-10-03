import base64
import binascii
from random import randint
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend


block_length = 16
key = b'asjdhwuajskdja!s'


def cbc_encrypt(b64text, iv):

	plaintext = base64.b64decode(b64text)

	pad = padding.PKCS7(8*block_length)
	aes = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

	padder = pad.padder()
	encryptor = aes.encryptor()

	padded_plaintext = padder.update(plaintext) + padder.finalize()
	ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

	return ciphertext

# This is the padding oracle. This function is the one that would have to
# be replaced in a real attack.
def is_valid_padding(ciphertext, iv):

	pad = padding.PKCS7(8*block_length)
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
	c_1 = ciphertext[:l - (2*block_size)]
	c_2 = ciphertext[l - (2*block_size):l - block_size]
	c_3 = ciphertext[l - block_size:]

	for i in range(block_size):
		mod = c_2[:i] + bytes([1^c_2[i]])+ c_2[i+1:]
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
		cut = len(c)-2*block_size
		c = c[:cut]
		c += original[len(c):len(c)+block_size]

	# Each byte in the cipher, up until the one we are currently trying to decipher,
	# is saved. These bytes will not be modified this round. All the modified bytes
	# will be appended to these at the end to create the new ciphertext
	first_c = c[:index]

	# This will hold all of the bytes that have changed this round
	second_c = b''

	# This will be all of the bytes that come after the modified bytes.
	third_c = c[len(c)-block_size:]

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
	p[len(p) - padding_bytes:] = bytes([padding_bytes])*padding_bytes

	ciphertext = original
	reverse = b''
	for i in range(len(p) - padding_bytes -1, -1, -1):
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

	to_encrypt = lines[randint(0,len(lines)-1)]

	ciphertext = cbc_encrypt(to_encrypt, iv)
	broken = attack_cbc(ciphertext, iv, 16)
	print(broken)


if __name__ == "__main__":
	main()