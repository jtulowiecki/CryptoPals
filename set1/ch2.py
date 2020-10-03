# Author: Joseph Tulowiecki
#
# https://cryptopals.com/sets/1/challenges/2
# Fixed XOR
#
# Write a function that takes two equal-length buffers and produces their XOR combination.
#
# If your function works properly, then when you feed it the string:
#
# 1c0111001f010100061a024b53535009181c
# ... after hex decoding, and when XOR'd against:
#
# 686974207468652062756c6c277320657965
# ... should produce:
#
# 746865206b696420646f6e277420706c6179

from jcrypt import conversions
import binascii

first = "1c0111001f010100061a024b53535009181c"
second = "686974207468652062756c6c277320657965"
third = "746865206b696420646f6e277420706c6179"

xor_result = binascii.hexlify(
    conversions.xor_bytes(
        binascii.unhexlify(first),
        binascii.unhexlify(second)
    )
).decode('ascii')

assert(xor_result == third)
