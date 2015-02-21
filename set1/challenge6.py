"""
Break repeating-key XOR
-----------------------

It is officially on, now.
This challenge isn't conceptually hard, but it involves actual error-prone
coding. The other challenges in this set are there to bring you up to speed.
This one is there to qualify you. If you can do this one, you're probably just
fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with
repeating-key XOR.

Decrypt it.

Here's how:

1. Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
2. Write a function to compute the edit distance/Hamming distance between two
   strings. The Hamming distance is just the number of differing bits.
   The distance between:
   this is a test
   and
   wokka wokka!!!
   is 37. Make sure your code agrees before you proceed.
3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second
   KEYSIZE worth of bytes, and find the edit distance between them. Normalize
   this result by dividing by KEYSIZE.
4. The KEYSIZE with the smallest normalized edit distance is probably the key.
   You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4
   KEYSIZE blocks instead of 2 and average the distances.
5. Now that you probably know the KEYSIZE: break the ciphertext into blocks of
   KEYSIZE length.
6. Now transpose the blocks: make a block that is the first byte of every
   block, and a block that is the second byte of every block, and so on.
7. Solve each block as if it was single-character XOR. You already have code to
   do this.
8. For each block, the single-byte XOR key that produces the best looking
   histogram is the repeating-key XOR key byte for that block. Put them
   together and you have the key.
This code is going to turn out to be surprisingly useful later on. Breaking
repeating-key XOR ("Vigenere") statistically is obviously an academic exercise,
a "Crypto 101" thing. But more people "know how" to break it than can actually
break it, and a similar technique breaks something much more important.

No, that's not a mistake.
We get more tech support questions for this challenge than any of the other
ones. We promise, there aren't any blatant errors in this text. In particular:
the "wokka wokka!!!" edit distance really is 37.
"""

import binascii
from multiprocessing import Pool
from challenge3 import decrypt, score

def b642hex(s):
    return binascii.hexlify(binascii.a2b_base64(s))

def repeated_key_xor_decrypt(s, max_len=40):
    """
    Decrypts a CT hex string that has been encrypted by a repeating key XOR.
    My method: For each key length from 2 to max_len, compute the best possible
               PT using all possible keys. Then, out of those max_len-1 PTs,
               take the best PT. Computing the best possible PT for a key of a
               given length is done as follows: For each k-interval substring
               of the CT offset by i, where k is the key length and
               0 <= i < len(CT), compute the score of the substring and take
               the PT with the best score.

    @param s [str]: CT (hex string)
    @param max_len [int]: Maximum repitition length of the repeating key.
    @returns [str]: PT (ASCII string)
    """

    def fixed_len_repeated_key_xor_decrypt(keylen):
        """
        Decrypts a CT hex string that has been encrypted by a repeating key
        XOR with a key of a known length

        @param keylen [int]: Repitition length of the repeating key.
        @returns [tuple]: ([int], [str], [int]) where t[0] is the score
                                                      t[1] is the PT
                                                      t[2] is the key length
        """

        p = Pool(10)
        pt_segments = p.map(decrypt, [''.join(ct_split[i::keylen])
                                      for i in range(keylen)])
        pt_score = sum([score(pt_segment) for pt_segment in pt_segments])
        # zip the segments
        pt = ''.join([pt_segments[j][i] for i in range(len(pt_segments[0]))
                                        for j in range(len(pt_segments))
                                        if i < len(pt_segments[j])])
        return (pt_score, pt, keylen)

    # Split the CT into bytes. 0-pad the front if necessary
    if len(s) % 2 == 1:
        s = '0' + s
    ct_split = [s[i:i+2] for i in range(0, len(s), 2)]

    attempts = []
    for keylen in range(2, max_len+1):
        result = fixed_len_repeated_key_xor_decrypt(keylen)
        attempts.append(result)
    return sorted(attempts, key=lambda x: x[0], reverse=True)[0]

if __name__=='__main__':
    filename = 'challenge6.txt'
    with open(filename, 'r') as f:
        txt = ''.join([line.strip() for line in f])
    hextxt = b642hex(txt)
    print repeated_key_xor_decrypt(hextxt)[1]
