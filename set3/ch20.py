from Crypto.Cipher import AES
from Crypto.Util import Counter
from os import urandom
import base64


def pycrypto_aes_128_ctr_encrypt(key, data):
    _ctr = Counter.new(64, initial_value=0, prefix=b'\x00'*8, little_endian=True)
    aes = AES.new(key, AES.MODE_CTR, counter=_ctr)
    return aes.encrypt(data)


def generate_ciphers():
    k = urandom(16)
    with open('../resources/ch20.txt', 'rb') as my_file:
        lines = my_file.readlines()
    with open('../resources/ch20_2.txt', 'w') as cipher_file:
        first = True
        for line in lines:
            if first:
                encrypted = pycrypto_aes_128_ctr_encrypt(k, base64.b64decode(line))
                cipher_file.write(base64.b64encode(encrypted).decode('ascii'))
                first = False
            else:
                cipher_file.write('\n')
                encrypted = pycrypto_aes_128_ctr_encrypt(k, base64.b64decode(line))
                cipher_file.write(base64.b64encode(encrypted).decode('ascii'))


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
    return max([getData(line, k) for k in range(256)], key=lambda x: x['score'])


def main():
    # generate_ciphers()
    key = b''
    data = []
    result = []
    with open('../resources/ch20_2.txt', 'rb') as my_file:
        lines = my_file.readlines()
    for line in lines:
        data.append(base64.b64decode(line))

    for i in range(100):
        key += bytes([getBestScoreForLine(bytes([data[x][i] for x in range(len(data)) if i < len(data[x])]))['key']])

    for c in data:
        result.append((bytes(x ^ y for x, y in list(zip(key, c[:100])))))
    print(result)


if __name__ == "__main__":
    main()