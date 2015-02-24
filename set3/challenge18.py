"""
Implement CTR, the stream cipher mode
-------------------------------------

The string:

L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==

... decrypts to something approximating English in CTR mode, which is an AES
block cipher mode that turns AES into a stream cipher, with the following
parameters:

      key=YELLOW SUBMARINE
      nonce=0
      format=64 bit unsigned little endian nonce,
             64 bit little endian block count (byte count / 16)

CTR mode is very simple.

Instead of encrypting the plaintext, CTR mode encrypts a running counter,
producing a 16 byte block of keystream, which is XOR'd against the plaintext.

For instance, for the first 16 bytes of a message with these parameters:

keystream = AES("YELLOW SUBMARINE",
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")

... for the next 16 bytes:

keystream = AES("YELLOW SUBMARINE",
            "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")

... and then:

keystream = AES("YELLOW SUBMARINE",
            "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")

CTR mode does not require padding; when you run out of plaintext, you just stop
XOR'ing keystream and stop generating keystream.

Decryption is identical to encryption. Generate the same keystream, XOR, and
recover the plaintext.

Decrypt the string at the top of this function, then use your CTR function to
encrypt and decrypt other things.

This is the only block cipher mode that matters in good code.
Most modern cryptography relies on CTR mode to adapt block ciphers into stream
ciphers, because most of what we want to encrypt is better described as a
stream than as a sequence of blocks. Daniel Bernstein once quipped to Phil
Rogaway that good cryptosystems don't need the "decrypt" transforms.
Constructions like CTR are what he was talking about.
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from challenge17 import b642hex, pkcs7_pad, xorstr

def aes_ctr_encrypt(k, pt, nonce):
    """
    Encrypts a message using AES in CTR mode. The nonce is 8-byte and little-
    endian. The counter is similarly 8-byte and little-endian. The input into
    the AES block cipher primitive is AES(key, nonce||ctr). For example, with
    an original nonce of:
        '\x00\x00\x00\x00\x00\x00\x00\xff'
    The keystream (nonce||ctr) inputs are:
        '\xff\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        '\xff\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00'
        ...
        '\xff\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00'
        '\xff\x00\x00\x00\x00\x00\x00\x00\xff\x01\x00\x00\x00\x00\x00\x00'
        ...
    The AES encryption algorithm is:
        C_i = E_k(key, f(nonce, ctr_i)) XOR P_i for all i, i != N
        Where E is the AES encryption primitive.
        In this case, f(nonce, ctr) is nonce || ctr.
        Since CTR mode doesn't pad inputs, the last block is:
            C_N = E_k(key, f(nonce, ctr_N))[:len(P_N)] XOR P_N for i == N

    @param k [str]: 16-byte ASCII string
    @param pt [str]: N-byte ASCII string
    @param nonce [str]: 8-byte ASCII string
    @returns [str] PT
    """

    def ecb_encrypt(k, pt):
        """
        FROM: set1/challenge7
        Decrypts a message encrypted using AES in ECB mode (assume the input is
        padded to the block size).
        """
        cipher = Cipher(algorithms.AES(k), modes.ECB(),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(pt) + encryptor.finalize()

    blocksize = 16
    if len(pt) > 256 ** 8:
        raise Exception('PT is too long.')
    if len(k) != blocksize:
        raise Exception('Key must be 16 bytes long.')
    if len(nonce) != blocksize / 2:
        raise Exception('Nonce must be 8 bytes long.')

    pt_blocks = [pt[i:i+blocksize] for i in range(0, len(pt), blocksize)]
    ct_blocks = []
    keystream = nonce + '\x00' * (blocksize / 2) # nonce || ctr
    for ctr, pt_block in enumerate(pt_blocks):
        # Convert to hex, chop the initial '0x', pad to the correct length.
        ctr_str = hex(ctr)[2:].zfill(blocksize)
        # Split into char bytes and reverse them for little-endianness
        ctr_arr = [ctr_str[i:i+2].decode('hex')
                   for i in range(0, len(ctr_str), 2)][::-1]
        keystream = nonce + ''.join(ctr_arr)
        # For PT that are not a multiple of blocksize, discard the remainder of
        # the keystream before XORing with the CT block
        ct_blocks.append(xorstr(ecb_encrypt(k, keystream)[:len(pt_block)],
                                pt_block))
    return ''.join(ct_blocks)

def aes_ctr_decrypt(k, ct, nonce):
    """
    Decrypts a message using AES in CTR mode. The nonce is 8-byte and little-
    endian. The counter is similarly 8-byte and little-endian. The input into
    the AES block cipher primitive is AES(key, nonce||ctr). For example, with
    an original nonce of:
        '\x00\x00\x00\x00\x00\x00\x00\xff'
    The keystream (nonce||ctr) inputs are:
        '\xff\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00'
        '\xff\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00'
        ...
        '\xff\x00\x00\x00\x00\x00\x00\x00\xff\x00\x00\x00\x00\x00\x00\x00'
        '\xff\x00\x00\x00\x00\x00\x00\x00\xff\x01\x00\x00\x00\x00\x00\x00'
        ...
    The AES decryption algorithm is:
        P_i = E_k(key, f(nonce, ctr_i)) XOR C_i for all i, i != N
        Where E is the AES encryption (NOT decryption) primitive.
        In this case, f(nonce, ctr) is nonce || ctr.
        Since CTR mode doesn't pad inputs, the last block is:
            P_N = E_k(key, f(nonce, ctr_N))[:len(C_N)] XOR C_N for i == N

    @param k [str]: 16-byte ASCII string
    @param ct [str]: N-byte ASCII string
    @param nonce [str]: 8-byte ASCII string
    @returns [str] PT
    """

    def ecb_encrypt(k, pt):
        """
        FROM: set1/challenge7
        Decrypts a message encrypted using AES in ECB mode (assume the input is
        padded to the block size).
        """
        cipher = Cipher(algorithms.AES(k), modes.ECB(),
                        backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(pt) + encryptor.finalize()

    blocksize = 16
    if len(ct) > 256 ** 8:
        raise Exception('CT is too long.')
    if len(k) != blocksize:
        raise Exception('Key must be 16 bytes long.')
    if len(nonce) != blocksize / 2:
        raise Exception('Nonce must be 8 bytes long.')

    ct_blocks = [ct[i:i+blocksize] for i in range(0, len(ct), blocksize)]
    pt_blocks = []
    keystream = nonce + '\x00' * (blocksize / 2) # nonce || ctr
    for ctr, ct_block in enumerate(ct_blocks):
        # Convert to hex, chop the initial '0x', pad to the correct length.
        ctr_str = hex(ctr)[2:].zfill(blocksize)
        # Split into char bytes and reverse them for little-endianness
        ctr_arr = [ctr_str[i:i+2].decode('hex')
                   for i in range(0, len(ctr_str), 2)][::-1]
        keystream = nonce + ''.join(ctr_arr)
        # For PT that are not a multiple of blocksize, discard the remainder of
        # the keystream before XORing with the CT block
        pt_blocks.append(xorstr(ecb_encrypt(k, keystream)[:len(ct_block)],
                                ct_block))
    return ''.join(pt_blocks)

if __name__=='__main__':
    k = 'YELLOW SUBMARINE'
    s = ('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLS'
         'FQ==')
    nonce = '\x00'*(len(k)/2)
    # Make sure decryption works
    msg = aes_ctr_decrypt(k, b642hex(s).decode('hex'), nonce)
    print msg
    # Make sure encryption works
    print aes_ctr_decrypt(k, aes_ctr_encrypt(k, msg, nonce), nonce)
