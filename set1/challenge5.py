"""
Implement repeating-key XOR
Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first
byte of plaintext will be XOR'd against I, the next C, the next E, then I again
for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your
mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise,
we aren't wasting your time with this.
"""

import binascii

def repeating_xor(k, s):
    """
    Plaintext encryption function E(k, s):
    - E: XOR
    - k: Repeating key k1k2...knk1k2...kn..., where k1k2...kn is the @param k
    - s: PT

    @param k [str]: Repeating key k1k2...kn
    @param s [str]: PT
    """

    def xor(c1, c2):
        """
        Zero-padded xor over two 16-bit characters. See challenge2.py for a
        (possibly) faster version.

        @param c1, c2 [str]: character
        @returns c1 ^ c2 [str]: 2-character hex digit in the range 0x00 - 0xff
        """
        return '%0.2x' % (ord(c1) ^ ord(c2))

    k_s = ''.join([k for _ in range(0, len(s)/len(k))]
                  + [k[:len(s) - len(s)/len(k) * len(k)]])
    return ''.join([xor(x, y) for x, y in zip(k_s, s)])

if __name__=='__main__':
    k = 'ICE'
    s = ('Burning \'em, if you ain\'t quick and nimble\n'
         'I go crazy when I hear a cymbal')
    print repeating_xor(k, s)
