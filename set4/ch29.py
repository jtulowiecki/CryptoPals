# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/1/challenges/4
# Detect single-character XOR
#
#

import binascii

MAX_WORD = 0xFFFFFFFF


def pre_process_msg(msg):
    original_length = len(msg) * 8
    msg += b'\x80'
    k = 64 - ((len(msg) + 8) % 64)
    msg += b'\x00' * k
    msg += original_length.to_bytes(8, byteorder='big')
    return msg


# The key length is in bytes
def get_glue_padding(original_msg, key_len):
    original_length = (len(original_msg) + key_len) * 8
    glue_padding = b'\x80'
    k = 64 - (((original_length//8 + 1) + 8) % 64)
    glue_padding += b'\x00' * k
    glue_padding += original_length.to_bytes(8, byteorder='big')
    return glue_padding


def left_rotate(num, offset):
    return ((num << offset) | (num >> (32 - offset))) & MAX_WORD


def process_msg(msg, h0, h1, h2, h3, h4):

    # For each 512 bit block
    for chunk in [msg[y * 64:(y + 1) * 64] for y in range(len(msg) // 64)]:

        # Break chunk into sixteen 32-bit big-endian words w[i], 0 ≤ i ≤ 15
        w = [int.from_bytes(chunk[x * 4:(x + 1) * 4], byteorder='big') for x in range(len(chunk) // 4)]

        # Message schedule: extend the sixteen 32-bit words into eighty 32-bit words
        for i in range(16, 80):
            w.append(left_rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))

        # Initialize hash value for this chunk
        a, b, c, d, e = h0, h1, h2, h3, h4

        # Main loop
        for i in range(80):
            if 0 <= i <= 19:
                f = (b & c) | ((~b) & d)
                k = 0x5A827999
            elif 20 <= i <= 39:
                f = b ^ c ^ d
                k = 0x6ED9EBA1
            elif 40 <= i <= 59:
                f = (b & c) | (b & d) | (c & d)
                k = 0x8F1BBCDC
            elif 60 <= i <= 79:
                f = b ^ c ^ d
                k = 0xCA62C1D6

            temp = left_rotate(a, 5) + f + e + k + w[i]
            e = d
            d = c
            c = left_rotate(b, 30)
            b = a
            a = temp

        # Add this chunk's hash to result so far
        h0 = (h0 + a) & MAX_WORD
        h1 = (h1 + b) & MAX_WORD
        h2 = (h2 + c) & MAX_WORD
        h3 = (h3 + d) & MAX_WORD
        h4 = (h4 + e) & MAX_WORD

    result = b''.join(H.to_bytes(4, byteorder='big') for H in [h0, h1, h2, h3, h4])
    return result


def sha1(msg):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0
    msg = pre_process_msg(msg)
    return binascii.hexlify(process_msg(msg, h0, h1, h2, h3, h4))


def sign_sha1_keyed_mac(key, msg):
    new_msg = key + msg
    tag = sha1(new_msg)
    return tag


def verify_sha1_keyed_mac(key, msg, tag):
    return sha1(key + msg) == tag


def forge_sha_sig(old_msg, old_digest, append_msg):
    if len(old_digest) is not 40:
        raise Exception('Bad Digest Length')

    hex_old_digest = binascii.unhexlify(old_digest)
    new_h = [int.from_bytes(hex_old_digest[i * 4:(i + 1) * 4], byteorder='big') for i in range(5)]

    # Get the appropriate padding for the secret key length
    prefix_len = 16
    old_glue_padding = get_glue_padding(old_msg, prefix_len)

    # Get the appropriate padding for the whole msg ( key, old_msg, glue_padding, append_msg, PADDING)
    append_glue_padding = get_glue_padding(append_msg, (prefix_len + len(old_msg) + len(old_glue_padding)))
    new_msg = append_msg + append_glue_padding
    new_digest = binascii.hexlify(process_msg(new_msg, new_h[0], new_h[1], new_h[2], new_h[3], new_h[4]))
    print(old_msg + old_glue_padding + append_msg)
    return (old_msg + old_glue_padding + append_msg), new_digest


# Would likely use %80%00 for encoding the glue padding if sent over http
def main():
    key = b'Yellow Submarine'
    msg = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    tag = sign_sha1_keyed_mac(key, msg)
    assert verify_sha1_keyed_mac(key, msg, tag)

    append_msg = b';admin=true'
    (new_msg, new_tag) = forge_sha_sig(msg, tag, append_msg)
    assert verify_sha1_keyed_mac(key, new_msg, new_tag)


if __name__ == "__main__":
    main()
