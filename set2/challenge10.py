"""
Implement CBC mode
------------------

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized
messages, despite the fact that a block cipher natively only transforms
individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before
the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block,
is added to a "fake 0th ciphertext block" called the initialization vector,
or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making
it encrypt instead of decrypt (verify this by decrypting whatever you encrypt
to test), and using your XOR function from the previous exercise to combine
them.

The file here is intelligible (somewhat) when CBC decrypted against
"YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

Don't cheat.
Do not use OpenSSL's CBC code to do CBC mode, even to verify your results.
What's the point of even doing this stuff if you aren't going to learn from it?
"""

"""
CBC algorithm:
    C_i = E_k(P_i XOR C_i-1); C_0 = IV
    P_i = D_k(C_i) XOR C_i-1; C_0 = IV
where:
    C_i: CT for block i
    E_k: AES encrypt with key k
    D_k: AES decrypt with key k
    P_i: PT for block i
    C_i-1: CT for block i-1
    C_0: Initialization vector
"""

import binascii
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from challenge9 import pkcs7_pad

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
    Performs a character-wise XOR for each character in strings @s1 and @s2.
    Assume that s1 and s2 are of equal length.

    @param s1, s2 [str]: ASCII strings
    @returns [str]: ASCII string
    """

    def xor(c1, c2):
        """
        @param c1, c2 [str]: Single byte ASCII characters
        @returns [str]: Single byte ASCII character
        """
        return chr(ord(c1) ^ ord(c2))

    return ''.join([xor(s1[i], s2[i]) for i in range(len(s1))])

def aes_ecb_encrypt(k, pt):
    """
    Encrypts a message using AES in ECB mode. Pads as necessary using PKCS#7.

    @param k [str]: key
    @param pt [str]: PT (ASCII string)
    @returns [str]: CT (ASCII string)
    """

    padded_pt = pkcs7_pad(pt, len(k))
    cipher = Cipher(algorithms.AES(k), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded_pt) + encryptor.finalize()

def aes_ecb_decrypt(k, ct):
    """
    FROM: set1/challenge7
    Decrypts a message encrypted using AES in ECB mode.

    @param k [str]: key
    @param ct [str]: CT (ASCII string)
    @returns [str]: PT (ASCII string)
    """

    cipher = Cipher(algorithms.AES(k), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ct) + decryptor.finalize()

def aes_cbc_encrypt(k, pt, iv):
    """
    Encrypts a message using AES in CBC mode. Pads as necessary using PKCS#7.

    @param k [str]: ASCII key
    @param pt [str]: ASCII PT string
    @param iv [str]: Initialization vector
    @returns [str]: ASCII CT string
    """

    def ecb_encrypt(k, pt):
        """
        Encrypts a message using AES in ECB mode (assume the input is padded to
        the block size).
        """
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
    Decrypts a message encrypted using AES in CBC mode.

    @param k [str]: ASCII key
    @param ct [str]: ASCII CT string
    @param iv [str]: Initialization vector
    @returns [str]: ASCII PT string
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

if __name__=='__main__':
    key = 'YELLOW SUBMARINE'
    with open('challenge10.txt', 'r') as f:
        txt = b642hex(''.join([line.strip() for line in f])).decode('hex')
    iv = chr(0) * len(key)
    print aes_cbc_decrypt(key, txt, iv)
    print hex2b64(aes_cbc_encrypt(
        key, aes_cbc_decrypt(key, txt, iv), iv
    ).encode('hex'))
