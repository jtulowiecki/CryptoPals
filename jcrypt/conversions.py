# Author: Joseph Tulowiecki
#
# Conversion utilities module for reusable cryptopals operations

import binascii
import base64


def s_hex_2_s_b64(s_hex):
    # Converts a hex string to a base 64 encoded string by first converting it
    # to bytes, base64 encoding the bytes, and decoding the result as an
    # ASCII string
    hexAsAscii = binascii.unhexlify(s_hex)
    return base64.b64encode(hexAsAscii).decode('ascii')


def xor_bytes(a, b):
    # Takes two sequences of bytes that are the same size and performs
    # and exclusive OR
    if len(a) != len(b):
        raise ValueError("xor_bytes requires arguments of equal length.")
    return bytes(x ^ y for x, y in list(zip(a, b)))
