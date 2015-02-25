"""
Break fixed-nonce CTR statistically
-----------------------------------

In this file find a similar set of Base64'd plaintext. Do with them exactly
what you did with the first, but solve the problem differently.

Instead of making spot guesses at to known plaintext, treat the collection of
ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR, but with a
fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a
common length (the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating- key XOR,
with a key size of the length of the ciphertext you XOR'd.
"""

from challenge17 import b642hex, rand_bytes, xorstr
from challenge18 import aes_ctr_encrypt, aes_ctr_decrypt
from challenge19 import charscore

class SessionOracle:

    __BLOCKSIZE = 16
    __FILENAME = 'challenge20.txt'

    def __init__(self):
        self.__key = rand_bytes(self.__BLOCKSIZE)
        self.__nonce = '\x00' * (self.__BLOCKSIZE / 2)
        self.__strings = self.__load_strings()

    def __load_strings(self):
        with open(self.__FILENAME, 'r') as f:
            strings = [l.strip() for l in f]
        return strings

    def get_encrypted_strings(self):
        return [aes_ctr_encrypt(self.__key,
                                b642hex(s).decode('hex'),
                                self.__nonce) for s in self.__strings]

def decrypt():
    """
    Instantiates a new SessionOracle and gets the list of all encrypted CTs.
    Using these CTs, it figures out the corresponding PTs. Approach:
        Note that for all i, P_i = C_i XOR E_k(keystream_i). Then, for all
        (PT, CT) pairs (PTn, CTn), Pn_i XOR Cn_i = Pm_i XOR Cm_i. So, we can
        guess each character of Pn_i and check that character against the 39
        other CTs. We'll take the highest score out of all 256 possible Pn_i
        and use that to find the rest of the Pm_i (Cn_i XOR Pn_i XOR Cm_i). Do
        this for all characters in all blocks. This should give us pretty
        reliable results for the first characters, but less reliable results
        for long strings, where there are fewer candidates to XOR against.

    @returns [list]: A list of decrypted ASCII PTs
    """

    oracle = SessionOracle()
    cts = oracle.get_encrypted_strings()
    maxlen = max(map(len, cts))
    # Pick Pn to be the longest string
    longeststr = [s for s in cts if len(s) == maxlen][0] # Pick the first one
    pt_n = ''
    # Figure out the PT for the longest string
    for stri in range(maxlen):
        cscores = []
        for c in map(chr, range(256)):
            cscore = sum([charscore(xorstr(xorstr(c, longeststr[stri]),
                                           ct[stri]))
                          for ct in cts if len(ct) > stri
                          and ct != longeststr])
            cscores.append((c, cscore))
        # Pick the first character with the max score
        pt_n += sorted(cscores, key=lambda x: x[1], reverse=True)[0][0]
    
    # Figure out the PT for the rest of the strings
    pts = [xorstr(xorstr(longeststr[:len(ct)], pt_n[:len(ct)]), ct)
           for ct in cts]
    return pts

if __name__ == '__main__':
    pts = decrypt()
    for pt in pts:
        print pt
