# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/1/challenges/6
# Break repeating-key XOR
#
# There's a file here. It's been base64'd after being encrypted with repeating-key XOR.
#
# Decrypt it.
#
# Here's how:
#
# 1 - Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
#
# 2 - Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is
# just the number of differing bits. The distance between:
# this is a test
# and
# wokka wokka!!!
# is 37. Make sure your code agrees before you proceed.
#
# 3 - For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and
# find the edit distance between them. Normalize this result by dividing by KEYSIZE.
#
# 4 - The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps
# with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
#
# 5 - Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
#
# 6 - Now transpose the blocks: make a block that is the first byte of every block, and a block that is the
# second byte of every block, and so on.
#
# 7 - Solve each block as if it was single-character XOR. You already have code to do this.
#
# 8 - For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key
# XOR key byte for that block. Put them together and you have the key.
#
# This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR
# ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people
# "know how" to break it than can actually break it, and a similar technique breaks something much
# more important.

import base64


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


def getSingleByteXorForBlock(block):
	return max([getData(block, k) for k in range(256)], key=lambda x: x['score'])['key']


# Converts a byte to a bit array
def b2b(b):
	bit_array = []
	current_mod = b
	for i in range(8, 0, -1):
		if current_mod >= 2**(i-1):
			bit_array += [True]
			current_mod = current_mod % 2**(i-1)
		else:
			bit_array += [False]
	return bit_array


# Calculates the edit distance for a single byte
def get_byte_e_dist(f_bits, s_bits):
	return len([True for x in range(8) if f_bits[x] != s_bits[x]])


# Calculates the edit distance for two byte arrays
def get_e_dist(f, s):
	if len(f) != len(s):
		raise ValueError
	return sum([get_byte_e_dist(b2b(f[i]), b2b(s[i])) for i in range(len(f))])


# Gets normalized edit distance for first block compared with all others for key size
def get_e_dist_for_key_size(secret, key_size):
	s_chunk = [secret[i:i + key_size] for i in range(0, len(secret), key_size)]  
	total = (sum([get_e_dist(s_chunk[0], s_chunk[i+1]) for i in range(len(secret)//key_size-1)]))
	result = {
		'e_dist': (total / (len(secret)//key_size-1)) / key_size,
		'key_size': key_size
	}
	return result


def get_likely_key_size(_min, _max, c):
	return min([get_e_dist_for_key_size(c, i) for i in range(_min, _max)], key = lambda x: x['e_dist'])


def decryptRepeatKeyXor(ciphertext, key):
	plaintext = b''
	for i in range(len(ciphertext)):
		plaintext += bytes([ciphertext[i] ^ key[i%len(key)]])
	return plaintext


def breakRepeatXor(min_key, max_key, ciphertext):
	key = b''
	key_size = get_likely_key_size(min_key, max_key, ciphertext)['key_size']
	blocks = [ciphertext[i:i + key_size] for i in range(0, len(ciphertext), key_size)] 
	if len(blocks[-1]) < key_size: del blocks[-1]
	for i in range(key_size):
		key += bytes([getSingleByteXorForBlock([x[i] for x in blocks])])
	return key


def main():
	with open('../resources/ch6.txt') as my_file:
		b64encoded = my_file.read()
	ciphertext = base64.b64decode(b64encoded)
	key = breakRepeatXor(2, 40, ciphertext)
	print(key)
	print(decryptRepeatKeyXor(ciphertext, key))


if __name__ == "__main__":
	main()