from cryptography.hazmat.primitives import padding

def unpad_bytes(p):
	pad = padding.PKCS7(8*16)
	unpadder = pad.unpadder()
	return unpadder.update(p) + unpadder.finalize()

def main():
	print(unpad_bytes(b'ICE ICE BABY\x04\x04\x04\x04'))

if __name__ == "__main__":
	main()