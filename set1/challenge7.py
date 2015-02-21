"""
AES in ECB mode
---------------

The Base64-encoded content in this file has been encrypted via AES-128 in ECB
mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like
"YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

Do this with code.
You can obviously decrypt this using the OpenSSL command-line tool, but we're
having you get ECB working in code for a reason. You'll need it a lot later on,
and not just for attacking ECB.
"""

"""
NOTE: Requires the cryptography package (https://cryptography.io/)
      $ pip install cryptography
"""

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from challenge6 import b642hex

def aes_ecb_decrypt(key, text):
    """
    Decrypts a message encrypted using AES in ECB mode.

    @param key [str]: key
    @param text [str]: CT (hex string)
    @returns [str]: PT (ASCII string)
    """

    ascii_text = text.decode('hex')
    cipher = Cipher(algorithms.AES(key), modes.ECB(),
                    backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ascii_text) + decryptor.finalize()

if __name__=='__main__':
    key = 'YELLOW SUBMARINE'
    with open('challenge7.txt', 'r') as f:
        txt = ''.join([line.strip() for line in f])
    hextxt = b642hex(txt)
    print aes_ecb_decrypt(key, hextxt)
