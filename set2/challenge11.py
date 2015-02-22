"""
An ECB/CBC detection oracle
---------------------------

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a
function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly)
before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC
the other half (just use random IVs each time for CBC). Use rand(2) to decide
which to use.

Detect the block cipher mode the function is using each time. You should end up
with a piece of code that, pointed at a block box that might be encrypting ECB
or CBC, tells you which one is happening.
"""

import random
from challenge10 import aes_ecb_encrypt, aes_cbc_encrypt

def rand_bytes(strlen):
    """
    Returns a string of @strlen random bytes.
    """
    return ''.join(map(chr,
                       [random.randint(0, 255) for _ in range(strlen)]))

def rand_bytes_range(minlen, maxlen):
    """
    Generates a random string of a random number of bytes from @minlen to
    @maxlen. The distribution of possible strings is uniform.
    """
    return rand_bytes(random.randint(minlen, maxlen))

def encryption_oracle(pt):
    """
    For the input @pt, pads it with 5-10 bytes on both sides, then encrypts it
    with either AES in ECB mode or AES in CBC mode with equal probability. The
    key and IV are randomly generated 16-byte strings.
    """

    key = rand_bytes(16)
    iv = rand_bytes(16) # In case the mode is CBC. Generate this before
                        # choosing the mode to protect against timing attacks.
    padded_pt = rand_bytes_range(5, 10) + pt + rand_bytes_range(5, 10)
    if random.randint(0, 1) == 0:
        # print True # Uncomment to check the oracle detector
        return aes_ecb_encrypt(key, padded_pt)
    else:
        # print False # Uncomment to check the oracle detector
        return aes_cbc_encrypt(key, padded_pt, iv)

def detect_encryption_oracle():
    """
    Calls an encryption oracle (some function that encrypts a plaintext) and
    returns True if the encryption mode was ECB and False if the encryption
    mode was CBC. This particular encryption oracle is described above. Since
    the blocksize of the encryption oracle is 16 bytes, the strategy is to feed
    it a 48-byte string with 16-byte repetitions
    (s[0..15] == s[16..31] == s[32..47]). Though the oracle pads the beginning
    and end of the string (the first block will be pseudorandom), it is
    guaranteed that the second and the third block will equal in ECB mode (and
    improbable that they will in CBC mode).
    """

    pt = 'YELLOW SUBMARINE' * 3
    ct = encryption_oracle(pt)
    return ct[16:32] == ct[32:48]

if __name__=='__main__':
    print detect_encryption_oracle()
