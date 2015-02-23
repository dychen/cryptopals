"""
CBC bitflipping attacks
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="

.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"

The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and
encrypt it under the random AES key.

The second function should decrypt the string and look for the characters
";admin=true;" (or, equivalently, decrypt, split the string on ";", convert
each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to
provide user input to it that will generate the string the second function is
looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish
this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext
block:

* Completely scrambles the block the error occurs in
* Produces the identical 1-bit error(/edit) in the next ciphertext block.

Stop and think for a second.
Before you implement this attack, answer this question: why does CBC mode have
this property?
"""

from challenge9 import pkcs7_pad
from challenge10 import aes_cbc_encrypt, aes_cbc_decrypt, xorstr
from challenge11 import rand_bytes

class SessionOracle:

    PREFIX = "comment1=cooking%20MCs;userdata="
    SUFFIX = ";comment2=%20like%20a%20pound%20of%20bacon"

    def __init__(self):
        self.__key = rand_bytes(16) # Establish a random 16-byte key and IV for
        self.__iv = rand_bytes(16)  # the length of this "session"

    def encrypt(self, pt):
        return aes_cbc_encrypt(self.__key,
                               self.PREFIX + pt + self.SUFFIX,
                               self.__iv)

    def decrypt(self, ct):
        return aes_cbc_decrypt(self.__key, ct, self.__iv)

    def admin_exists(self, ct):
        """
        Detects if the admin parameter has been set to true in an input
        encrypted CT.

        @param ct [str]: Encrypted param string.
        @returns [bool]: True if, when decrypted, the string contains
                         ';admin=true;', False otherwise.
        """
        pt = aes_cbc_decrypt(self.__key, ct, self.__iv)
        vals = [tup for tup in [param.split('=') for param in pt.split(';')]
                if len(tup) == 2 and tup[0] == 'admin' and tup[1] == 'true']
        return len(vals) > 0

def create_admin(pt, ct):
    """
    Consider the CBC decryption algorithm:
        P_i = D_k(C_i) XOR C_i-1; C_0 = IV for all blocks i
    We wish to construct a modified CT C' that when decrypted gives us the
    desired string ';admin=true;'. So, if we were to find C' such that the ith
    block would contain P_i' = ';admin=true;\x04\x04\x04\x04', we need to find
    C'_i-1 = P_i' XOR D_k(C_i). Since P_i = D_k(C_i) XOR C_i-1 and we have
    both P and C (and hence P_i and C_i-1), we can rewrite
    D_k(C_i) = P_i XOR C_i-1. So, C'_i-1 = P_i' XOR P_i XOR C_i-1.
    Assume we know the blocksize is 16 bytes.
    """

    blocksize = 16
    idx = 2 # Rewrite the second block of the CT to produce a PT with a
            # scrambled second block and our target 3rd block. idx is i-1
    block_text = pkcs7_pad(';admin=true;', blocksize)
    ct_blocks = [ct[i:i+blocksize] for i in range(0, len(ct), blocksize)]
    pt_blocks = [pt[i:i+blocksize] for i in range(0, len(pt), blocksize)]
    ct_new_block = xorstr(xorstr(block_text, pt_blocks[idx+1]), ct_blocks[idx])
    ct_blocks[idx] = ct_new_block
    return ''.join(ct_blocks)

if __name__ == '__main__':
    oracle = SessionOracle()
    pt = 'somerandomstring'
    # For some random PT, encrypt it with the oracle
    ct = oracle.encrypt(pt)
    # Show that for the corresponding CT, the decrypted version does not
    # contain ';admin=true;' (because the PT was just 'somerandomstring'
    print oracle.admin_exists(ct)
    # Show that, after running the (PT, CT) pair through our attack script, we
    # can generate a valid CT that will contain the substring ';admin=true;'
    print oracle.admin_exists(
        create_admin(oracle.PREFIX + pt + oracle.SUFFIX, ct)
    )
    # See the decrypted PT of the CT string we created
    print oracle.decrypt(create_admin(oracle.PREFIX + pt + oracle.SUFFIX, ct))
