import binascii

def isPotentialAesEcbEncrypted(secret):
	block_size = 16
	if len(secret) % 16 != 0:
		return False

	blocks = [secret[i:i + block_size] for i in range(0, len(secret), block_size)]
	for i in range(len(blocks)):
		for x in range((i+1),len(blocks)):
			if blocks[i] == blocks[x]:
				return True
	return False

def findAesEncryptedCipher(lines):
	return [line for line in lines if isPotentialAesEcbEncrypted(line)]


def main():
	with open('../resources/ch8.txt') as my_file:
		lines = my_file.readlines()
	result = findAesEncryptedCipher([bytes.fromhex(line) for line in lines])
	for x in result:
		print(binascii.hexlify(x))

if __name__ == "__main__":
	main()