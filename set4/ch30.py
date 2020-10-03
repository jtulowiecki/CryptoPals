def get_padding(msg):
    original_length = len(msg) * 8
    padding = b'\x80'
    k = 64 - (((original_length // 8 + 1) + 8) % 64)
    padding += b'\x00' * k
    padding += original_length.to_bytes(8, byteorder='big')
    return padding

