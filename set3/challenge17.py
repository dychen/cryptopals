"""
The CBC padding oracle
----------------------

This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93

... generate a random AES key (which it should save for all future
encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt
it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first
function, decrypt it, check its padding, and return true or false depending on
whether the padding is valid.

What you're doing here.
This pair of functions approximates AES-CBC encryption as its deployed
serverside in web applications; the second function models the server's
consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the
first function.

The decryption here depends on a side-channel leak by the decryption function.
The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it.
What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid
padding, and occur in 1/256 trials of "randomized" plaintexts produced by
decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding,
you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded".
Padding oracles have nothing to do with the actual padding on a CBC plaintext.
It's an attack that targets a specific bit of code that handles decryption.
You can mount a padding oracle on any CBC block, whether it's padded or not.
"""

import binascii
import random
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def b642hex(s):
    """
    FROM: set1/challenge6
    """
    return binascii.hexlify(binascii.a2b_base64(s))

def hex2b64(s):
    """
    FROM: set1/challenge6
    """
    return binascii.b2a_base64(binascii.unhexlify(s))

def xorstr(s1, s2):
    """
    FROM: set2/challenge10
    """

    def xor(c1, c2):
        return chr(ord(c1) ^ ord(c2))

    return ''.join([xor(s1[i], s2[i]) for i in range(len(s1))])

def pkcs7_pad(s, length):
    """
    FROM: set2/challenge9
    """

    pad = length - len(s) % length
    return s + chr(pad) * pad

def valid_pkcs7_padding(s):
    """
    FROM set2/challenge15
    """

    last = ord(s[-1])
    if len(set(map(ord, s[-last:]))) == 1:
        return True
    else:
        raise Exception('Not a valid PKCS#7 encoding for string %s' % s)

def rand_bytes(strlen):
    """
    FROM: set2/challenge11
    """
    return ''.join(map(chr,
                       [random.randint(0, 255) for _ in range(strlen)]))

def aes_cbc_encrypt(k, pt, iv):
    """
    FROM: set2/challenge10
    """

    def ecb_encrypt(k, pt):
        cipher = Cipher(algorithms.AES(k), modes.ECB(),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(pt) + encryptor.finalize()

    padded_pt = pkcs7_pad(pt, len(k))
    pt_list = [padded_pt[i:i+len(k)] for i in range(0, len(padded_pt), len(k))]
    ct_list = [iv]
    for i in range(len(pt_list)):
        ct_list.append(ecb_encrypt(k, xorstr(ct_list[-1], pt_list[i])))
    return ''.join(ct_list[1:]) # Remove the IV

def aes_cbc_decrypt(k, ct, iv):
    """
    FROM: set2/challenge10
    """

    def ecb_decrypt(k, ct):
        """
        FROM: set1/challenge7
        Decrypts a message encrypted using AES in ECB mode (assume the input is
        padded to the block size).
        """
        cipher = Cipher(algorithms.AES(k), modes.ECB(),
                        backend=default_backend())
        decryptor = cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    ct_list = [iv]
    ct_list += [ct[i:i+len(k)] for i in range(0, len(ct), len(k))]
    pt_list = [xorstr(ecb_decrypt(k, ct_list[i+1]), ct_list[i])
               for i in range(len(ct_list)-1)]
    return ''.join(pt_list)

class Webserver:

    __STRINGS = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        ('MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1'
         'bXBpbic='),
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
    ]

    def __init__(self):
        self.__key = rand_bytes(16)

    def choose_random_string(self):
        """
        @returns [tuple] ([str], [str]) t[0] is the CT of a random string from
                         the set of secret strings, t[1] is the IV used to
                         encrypt that string
        """

        s = b642hex(random.choice(self.__STRINGS)).decode('hex')
        iv = rand_bytes(16)
        ct = aes_cbc_encrypt(self.__key, s, iv)
        return (ct, iv)

    def valid_padding(self, ct, iv):
        """
        @param ct [str]: ASCII CT
        @param iv [str]: IV used to encrypt the PT
        @returns [bool] True if the decrypted PT is correctly padded, False
                        otherwise
        """

        pt = aes_cbc_decrypt(self.__key, ct, iv)
        try:
            return valid_pkcs7_padding(pt)
        except Exception, e: # valid_pkcs7_padding raises an Exception if the
                             # padding is not valid
            return False

def decrypt(server, ct, iv):
    """
    Approach:
    Consider the CBC decryption algorithm:
        P_i = D_k(C_i) XOR C_i-1; C_0 = IV for all blocks i
    Let's construct a modified CT C' where C'_n-1 != C_n-1 and C'_i == C_i for
    all other blocks i, i != n-1. Let C'_n-1[-1] = 0x00..0xff (the last byte of
    C'_n ranges from 0x00 to 0xff). Then, feed C' into the Webserver's pad
    checking method. If it verifies, that means with high probability that
    P'_n[-1] == \x01. Note that from the definition,
    D_k(C_i) = P_i XOR C_i-1 = P'_i XOR C'_i-1 for all i. This implies that
    P_n[-1] = C_n-1[-1] XOR P'_n[-1] XOR C'_n-1[-1]. In other words, the last
    byte of the desired PT is equal to the result of XORing:
        1. the last byte of the next-to-last block of the original CT
        2. \x01 (the last byte of the fake PT from the modified CT)
        3. the last byte of the next-to-last block of the modified CT
    For the second to last byte, an input of C'_n-1[-2] = 0x00..0xff gives us a
    PT where P[-2:] is equal to the result of XORing:
        1. the last two bytes of the next-to-last block of the original CT
        2. \x02\x02 (the last two bytes of the fake PT from the modified CT)
        3. the next-to-last byte of the modified CT with the last byte of the
           modified CT C'[-1] XOR \x01 XOR \x02 (because we need to get the pad
           to equal \x02\x02).
    Repeat this for the rest of the bytes in the block, checking if the
    modified byte of the ith CT returns a valid PT (with padding chr(i) * i).
    Do this for all blocks, using the IV as C_0 to get the block P_1.
    """

    def strip_padding(s):
        """
        Strips PKCS#7 padding from a plaintext string.
        """

        return s[:-ord(s[-1])]

    blocksize = len(iv)
    ct_blocks = [iv] + [ct[i:i+blocksize]                      # List of block
                        for i in range(0, len(ct), blocksize)] # strings
    pt_blocks = []
    for blockidx in range(len(ct_blocks)-1, 0, -1):
        ct_blocks_mod = ct_blocks[:]
        pt_block = ''
        for byteidx in range(15, -1, -1):
            for testchar in map(chr, range(256)):
                # Tweak the character at the index given by blockidx, byteidx
                ct_blocks_mod[blockidx-1] = (
                    ct_blocks_mod[blockidx-1][:byteidx]
                    + testchar
                    + ct_blocks_mod[blockidx-1][byteidx+1:]
                )
                if server.valid_padding(
                    ''.join(ct_blocks_mod[blockidx-1:blockidx+1]),
                    iv
                ):
                    pt_byte = xorstr(xorstr(ct_blocks[blockidx-1][byteidx],
                                            chr(16 - byteidx)),
                                     testchar)
                    pt_block = pt_byte + pt_block
                    # Update the rest of the block for the next byte.
                    # Currently, our CT is correctly padded to find \0x01. We
                    # want to tweak the trailing bytes to find \0x02.
                    ct_blocks_mod[blockidx-1] = (
                        ct_blocks_mod[blockidx-1][:byteidx]
                        + ''.join([xorstr(xorstr(chr(16 - byteidx),
                                                 chr(16 - byteidx + 1)),
                                          currchar)
                                   for currchar
                                   in ct_blocks_mod[blockidx-1][byteidx:]])
                    break
        pt_blocks = [pt_block] + pt_blocks
    return strip_padding(''.join(pt_blocks))

if __name__=='__main__':
    server = Webserver()
    ct, iv = server.choose_random_string()
    print decrypt(server, ct, iv)
