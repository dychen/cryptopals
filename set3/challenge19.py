"""
Break fixed-nonce CTR mode using substitions
--------------------------------------------

Take your CTR encrypt/decrypt function and fix its nonce value to 0. Generate a
random AES key.

In successive encryptions (not in one big running CTR stream), encrypt each
line of the base64 decodes of the following, producing multiple independent
ciphertexts:

[See code]

(This should produce 40 short CTR-encrypted ciphertexts).

Because the CTR nonce wasn't randomized for each encryption, each ciphertext
has been encrypted against the same keystream. This is very bad.

Understanding that, like most stream ciphers (including RC4, and obviously any
block cipher run in CTR mode), the actual "encryption" of a byte of data boils
down to a single XOR operation, it should be plain that:

CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
And since the keystream is the same for every ciphertext:

CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
say!")
Attack this cryptosystem piecemeal: guess letters, use expected English
language frequence to validate guesses, catch common English trigrams, and so
on.

Don't overthink it.
Points for automating this, but part of the reason I'm having you do this is
that I think this approach is suboptimal.
"""

from challenge17 import b642hex, rand_bytes, xorstr
from challenge18 import aes_ctr_encrypt, aes_ctr_decrypt

def charscore(c):
    """
    FROM: set1/challenge3
    """

    # +1 if string is in the set of characters or spaces
    positive_set = set(range(ord('a'), ord('a')+26) + [ord(' ')])
    # -1 if the string is in the set of rarely used characters:
    #   128, 153, 161-255
    negative_set = set([128] + [153] + range(161, 255))
    # -99 if the string is in the set of unused characters:
    #   0-8, 11-31, 127, 129-152, 154-160
    unused_set = set(range(0, 9) + range(11, 32) + [127] + range(129, 153)
                     + range(154, 161))
    if ord(c) in positive_set:
        return 1
    elif ord(c) in negative_set:
        return -9
    elif ord(c) in unused_set:
        return -99
    else:
        return 0

class SessionOracle:

    __BLOCKSIZE = 16
    __STRINGS = ['SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
        'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
        'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
        'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
        'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
        'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
        'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
        'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
        'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
        'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
        'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
        'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
        'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
        'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
        'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
        'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
        'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
        'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
        'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
        'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
        'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
        'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
        'U2hlIHJvZGUgdG8gaGFycmllcnM/',
        'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
        'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
        'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
        'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
        'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
        'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
        'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
        'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
        'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
        'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
        'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
        'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
        'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
        'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
        'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
        'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
        'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
    ]

    def __init__(self):
        self.__key = rand_bytes(self.__BLOCKSIZE)
        self.__nonce = '\x00' * (self.__BLOCKSIZE / 2)

    def get_encrypted_strings(self):
        return [aes_ctr_encrypt(self.__key,
                                b642hex(s).decode('hex'),
                                self.__nonce) for s in self.__STRINGS]

def decrypt():
    """
    Instantiates a new SessionOracle and gets the list of all encrypted CTs.
    Using these CTs, it figures out the corresponding PTs. Approach:
        Note that for all i, P_i = C_i XOR E_k(keystream_i). So, let's try to
        guess E_k(keystream_i). For all characters 256 possible characters of
        E_k, pick the one where E_k XOR C_i produces the most legitimate
        characters (potential P_i) over all C_i. Do this for all characters.

    @returns [list]: A list of decrypted ASCII PTs
    """

    oracle = SessionOracle()
    cts = oracle.get_encrypted_strings()
    maxlen = max(map(len, cts))
    # Pick Pn to be the longest string
    longeststr = [s for s in cts if len(s) == maxlen][0] # Pick the first one
    enc_keystream = '' # Encrypted keystream E_k
    # Figure out the PT for the longest string
    for stri in range(maxlen):
        cscores = []
        for c in map(chr, range(256)):
            cscore = sum([charscore(xorstr(ct[stri], c))
                          for ct in cts if len(ct) > stri
                          and ct != longeststr])
            cscores.append((c, cscore))
        # Pick the first character with the max score
        enc_keystream += \
            sorted(cscores, key=lambda x: x[1], reverse=True)[0][0]

    # Figure out the PT for the CTs using the estimated E_k as input
    pts = [xorstr(enc_keystream[:len(ct)], ct) for ct in cts]
    return pts

if __name__ == '__main__':
    pts = decrypt()
    for pt in pts:
        print pt
