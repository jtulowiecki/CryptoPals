import binascii

MAX_WORD = 0xFFFFFFFF


def pre_process_msg(msg):
    original_length = len(msg) * 8
    msg += b'\x80'
    k = 64 - ((len(msg) + 8) % 64)
    msg += b'\x00' * k
    msg += original_length.to_bytes(8, byteorder='big')
    return msg


def left_rotate(num, offset):
    return ((num << offset) | (num >> (32 - offset))) & MAX_WORD


def process_msg(msg):
    h0 = 0x67452301
    h1 = 0xEFCDAB89
    h2 = 0x98BADCFE
    h3 = 0x10325476
    h4 = 0xC3D2E1F0

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

    # Produce the final hash value (big-endian) as a 160-bit number
    result = b''.join(H.to_bytes(4, byteorder='big') for H in [h0, h1, h2, h3, h4])
    return result


def sha1(msg):
    msg = pre_process_msg(msg)
    return binascii.hexlify(process_msg(msg))


def sign_sha1_keyed_mac(key, msg):
    new_msg = key + msg
    tag = sha1(new_msg)
    return tag


def verify_sha1_keyed_mac(key, msg, tag):
    return sha1(key + msg) == tag


def main():
    key = b'Yellow Submarine'
    msg = b'This is the message that will be signed.'
    tag = sign_sha1_keyed_mac(key, msg)
    assert verify_sha1_keyed_mac(key, msg, tag)

    msg = b'This is the nessage that will be signed.'
    assert not verify_sha1_keyed_mac(key, msg, tag)


if __name__ == "__main__":
    main()
