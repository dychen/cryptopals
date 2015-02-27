"""
Recover the key from CBC with IV=Key
------------------------------------

Take your code from the CBC exercise and modify it so that it repurposes the
key for CBC encryption as the IV.

Applications sometimes use the key as an IV on the auspices that both the
sender and the receiver have to know the key already, and can save some space
by using it as both a key and an IV.

Using the key as an IV is insecure; an attacker that can modify ciphertext in
flight can get the receiver to decrypt a value that will reveal the key.

The CBC code from exercise 16 encrypts a URL string. Verify each byte of the
plaintext for ASCII compliance (ie, look for high-ASCII values). Noncompliant
messages should raise an exception or return an error that includes the
decrypted plaintext (this happens all the time in real systems, for what it's
worth).

Use your code to encrypt a message that is at least 3 blocks long:

AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
Modify the message (you are now the attacker):

C_1, C_2, C_3 -> C_1, 0, C_1
Decrypt the message (you are now the receiver) and raise the appropriate error
if high-ASCII is found.

As the attacker, recovering the plaintext from the error, extract the key:

P'_1 XOR P'_3
"""

from challenge25 import rand_bytes, xorstr, pkcs7_pad
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SessionOracle:
    """
    A CBC session Oracle whose public API include encrypting and decrypting.
    The Oracle insecurely sets the IV equal to the key.
    """

    __BLOCKSIZE = 16
    # Set of unused ASCII characters    
    __UNUSED_SET = set(map(chr, list(range(0, 9) + range(11, 32) + [127]
                                     + range(129, 153) + range(154, 161))))

    def __init__(self):
        # Establish a random 16-byte key and iv for the length of the "session"
        self.__key = rand_bytes(self.__BLOCKSIZE)
        self.__iv = self.__key
        self.__cipher = Cipher(algorithms.AES(self.__key),
                               modes.CBC(self.__iv),
                               backend=default_backend())

    def encrypt(self, pt):
        pt = pkcs7_pad(pt, self.__BLOCKSIZE)
        encryptor = self.__cipher.encryptor()
        return encryptor.update(pt) + encryptor.finalize()

    def decrypt(self, ct):
        """
        Decrypts an input CT and raises an Exception if the decrypted PT is not
        ASCII-compliant.
        """
        decryptor = self.__cipher.decryptor()
        pt = decryptor.update(ct) + decryptor.finalize()
        #for c in pt:
        #    if c in self.__UNUSED_SET:
        #        raise Exception('Invalid input %s (returned %s)' % (ct, pt))
        return pt

def recover_key(oracle):
    blocksize = 16
    target_pt = 'A' * blocksize + 'B' * blocksize + 'C' * blocksize
    target_ct = oracle.encrypt(target_pt)
    target_ct_blocks = [target_ct[i:i+blocksize]
                        for i in range(0, len(target_ct), blocksize)]
    new_ct = target_ct_blocks[0] + '\x00' * blocksize + target_ct_blocks[0]
    try:
        new_pt = oracle.decrypt(new_ct)
        new_pt_blocks = [new_pt[i:i+blocksize]
                         for i in range(0, len(new_pt), blocksize)]
        key = xorstr(new_pt_blocks[0], new_pt_blocks[2])
        return key
    except Exception, e:
        print e
        print e.message[-blocksize-1:-1].encode('hex')

def check_key(oracle, key):

    def aes_cbc_encrypt(key, pt):
        pt = pkcs7_pad(pt, 16)
        cipher = Cipher(algorithms.AES(key),
                        modes.CBC(key),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(pt) + encryptor.finalize()

    check_pt = ('I been Steph Curry with the shot, Been cookin\' with the'
                'sauce, chef, curry in the pot, boy')
    print 'CT with our key: %s' % aes_cbc_encrypt(key, check_pt).encode('hex')
    print 'Oracle CT:       %s' % oracle.encrypt(check_pt).encode('hex')

if __name__=='__main__':
    oracle = SessionOracle()
    key = recover_key(oracle)
    # Print the recovered key
    print key.encode('hex')
    # Now that we have the key, we can encrypt a message and verify it against
    # the CT the oracle returns.
    check_key(oracle, key)
