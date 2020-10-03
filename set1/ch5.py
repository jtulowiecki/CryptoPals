import binascii


def encryptXor(plaintext, key):
	ciphertext = b''
	for i in range(len(plaintext)):
		ciphertext += bytes([plaintext[i] ^ key[i%len(key)]])
	return ciphertext


def main():
	key = b'ICE'
	with open('../resources/ch5.txt', "rb") as my_file:
		plaintext = my_file.read()
	ciphertext = encryptXor(plaintext, key)
	print(binascii.hexlify(ciphertext).decode('ascii'))


if __name__ == "__main__":
	main()