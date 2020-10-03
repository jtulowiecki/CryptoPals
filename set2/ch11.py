from random import randrange
from os import urandom
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

block_length = 16


def ecb_encrypt(plaintext, key):
    pad = padding.PKCS7(8 * block_length)
    aes = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

    padder = pad.padder()
    encryptor = aes.encryptor()

    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext


def ecb_decrypt(ciphertext, key):
    pad = padding.PKCS7(8 * block_length)
    aes = Cipher(algorithms.AES(key), modes.ECB(), default_backend())

    unpadder = pad.unpadder()
    decryptor = aes.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def cbc_encrypt(plaintext, key, iv):
    pad = padding.PKCS7(8 * block_length)
    aes = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

    padder = pad.padder()
    encryptor = aes.encryptor()

    padded_plaintext = padder.update(plaintext) + padder.finalize()
    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    return ciphertext


def cbc_decrypt(ciphertext, key, iv):
    pad = padding.PKCS7(8 * block_length)
    aes = Cipher(algorithms.AES(key), modes.CBC(iv), default_backend())

    unpadder = pad.unpadder()
    decryptor = aes.decryptor()

    padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()

    return plaintext


def encryption_oracle(p):
    key = urandom(block_length)
    before = urandom(randrange(6) + 5)
    after = urandom(randrange(6) + 5)
    plaintext = before + p + after

    if randrange(2) == 0:
        ciphertext = ecb_encrypt(plaintext, key)
        return {
            'mode': 'ECB',
            'ciphertext': ciphertext
        }

    else:
        iv = urandom(block_length)
        ciphertext = cbc_encrypt(plaintext, key, iv)
        return {
            'mode': 'CBC',
            'ciphertext': ciphertext
        }


def detect_ecb_or_cbc(ciphertext):
    block_length = 16
    if len(ciphertext) % block_length != 0:
        raise ValueError

    blocks = [ciphertext[i:i + block_length] for i in range(0, len(ciphertext), block_length)]
    for i in range(len(blocks)):
        for x in range((i + 1), len(blocks)):
            if blocks[i] == blocks[x]:
                return 'ECB'
    return 'CBC'


def main():
    detection_text = b'A' * 47
    attempts = 100000

    correct = 0
    for i in range(attempts):
        encrypted = encryption_oracle(detection_text)
        mode = detect_ecb_or_cbc(encrypted['ciphertext'])
        if mode == encrypted['mode']:
            correct = correct + 1

    score = (correct / attempts) * 100
    print('Accuracy: {:f} %'.format(score))


if __name__ == "__main__":
    main()
