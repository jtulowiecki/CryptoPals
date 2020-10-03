# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/1/challenges/3
# Single-byte XOR cipher

# The hex encoded string:
#
# 1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
#
# has been XOR'd against a single character. Find the key, decrypt the message.
#
# You can do this by hand. But don't: write code to do it for you.
#
# How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric.
# Evaluate each output and choose the one with the best score.

from jcrypt import frequencies


def single_char_xor(input_bytes, char_value):
    output_bytes = b''
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_value])
    return output_bytes


def getData(ciphertext, key, lang):
    message = single_char_xor(ciphertext, key)
    score = frequencies.get_freq_score(message, lang)
    data = {
        'ciphertext': ciphertext,
        'message': message,
        'score': score,
        'key': key
    }
    return data


def getBestScoreForLine(line, l):
    c = bytes.fromhex(line)
    return max([getData(c, k, l) for k in range(256)], key=lambda x: x['score'])


def main():
    hexstring = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    print(getBestScoreForLine(hexstring, frequencies.english))


if __name__ == "__main__":
    main()
