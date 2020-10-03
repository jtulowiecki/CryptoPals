from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from Crypto.Util import Counter
import base64


class Custom_CTR:

    def __init__(self, key):
        self.aes_custom = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

    def custom_aes_128_ctr_keystream_generator(self, nonce, counter):
        while True:
            to_encrypt = (nonce.to_bytes(length=8, byteorder='little')
                          + counter.to_bytes(length=8, byteorder='little'))
            encryptor = self.aes_custom.encryptor()
            keystream_block = encryptor.update(to_encrypt) + encryptor.finalize()
            yield from keystream_block
            counter += 1

    def custom_aes_128_ctr_encrypt(self, nonce, counter, data):
        result = b''
        my_gen = self.custom_aes_128_ctr_keystream_generator(nonce, counter)
        for i in range(len(data)):
            result += bytes([next(my_gen) ^ data[i]])
        return result


def pycrypto_aes_128_ctr_encrypt(key, data):
    _ctr = Counter.new(64, initial_value=0, prefix=b'\x00'*8, little_endian=True)
    aes = AES.new(key, AES.MODE_CTR, counter=_ctr)
    return aes.encrypt(data)


k = b'YELLOW SUBMARINE'
ctr = Custom_CTR(k)
enc = base64.b64decode(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
print('custom ctr:', ctr.custom_aes_128_ctr_encrypt(0, 0, enc))
print('hazmat ctr:', pycrypto_aes_128_ctr_encrypt(k, enc))