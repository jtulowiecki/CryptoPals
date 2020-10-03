from cryptography.hazmat.primitives import padding

def padBytes(text, block_length):
	padder = padding.PKCS7(8*block_length).padder()
	return padder.update(text) += padder.finalize()

def main():
	text = 'YELLOW SUBMARINE'.encode('utf-8')
	print(padBytes(text,20))
	
if __name__ == "__main__":
	main()