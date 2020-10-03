# Author: Joseph Tulowiecki
#
# A collection of dictionaries that contain a mapping of how frequently a particular character
# occurs in the language as well as a function to calculate the frequency of a series bytes for
# a given language.

english = {
    'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
    'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
    'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
    'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
    'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
    'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
    'y': .01974, 'z': .00074, ' ': .13000
}


def get_freq_score(input_bytes, lang):
    # Takes a sequence of bytes and returns a score of how likely the bytes represent plaintext
    # of a given language. The higher the score, the more likely it is the chosen language.

    return sum(
        [lang.get(chr(byte), 0) for byte in input_bytes.lower()]
    ) / len(input_bytes)
