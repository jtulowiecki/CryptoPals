# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/1/challenges/4
# Detect single-character XOR
#
# One of the 60-character strings in this file has been encrypted by single-character XOR.
#
# Find it.
#
# (Your code from #3 should help.)

import binascii


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
	c = bytes.fromhex(line)
	return max([getData(c, k) for k in range(256)], key = lambda x: x['score'])

def getBestScoreForAllLines(lines):
	return max([getBestScoreForLine(l) for l in lines], key = lambda x: x['score'])

def main():
	with open('../resources/ch4.txt') as my_file:
		lines = my_file.readlines()
	result = getBestScoreForAllLines(lines)
	print(binascii.hexlify(result['ciphertext']).decode('ascii'))

if __name__ == "__main__":
	main()