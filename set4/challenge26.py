"""
CTR bitflipping
---------------

There are people in the world that believe that CTR resists bit flipping
attacks of the kind to which CBC mode is susceptible.

Re-implement the CBC bitflipping exercise from earlier to use CTR mode instead
of CBC mode. Inject an "admin=true" token.
"""

from challenge25 import rand_bytes, xorstr
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class SessionOracle:
    """
    The same oracle from challenge 16 except using CTR instead of CBC. The
    public API is:
        encrypt(str)
        admin_exists(str)
    """

    __BLOCKSIZE = 16
    PREFIX = "comment1=cooking%20MCs;userdata="
    SUFFIX = ";comment2=%20like%20a%20pound%20of%20bacon"

    def __init__(self):
        # Establish a random 16-byte key and nonce for the length of the
        # "session"
        self.__key = rand_bytes(self.__BLOCKSIZE)
        self.__nonce = rand_bytes(self.__BLOCKSIZE)
        self.__cipher = Cipher(algorithms.AES(self.__key),
                               modes.CTR(self.__nonce),
                               backend=default_backend())

    def encrypt(self, pt):
        encryptor = self.__cipher.encryptor()
        return encryptor.update(pt) + encryptor.finalize()

    def __decrypt(self, ct):
        decryptor = self.__cipher.decryptor()
        return decryptor.update(ct) + decryptor.finalize()

    def admin_exists(self, ct):
        """
        Detects if the admin parameter has been set to true in an input
        encrypted CT.

        @param ct [str]: Encrypted param string.
        @returns [bool]: True if, when decrypted, the string contains
                         ';admin=true;', False otherwise.
        """

        pt = self.__decrypt(ct)
        vals = [tup for tup in [param.split('=') for param in pt.split(';')]
                if len(tup) == 2 and tup[0] == 'admin' and tup[1] == 'true']
        return len(vals) > 0

def ctr_bitflip(pt, ct, payload, offset=0):
    """
    As discussed in challenge 25, due to the construction of CTR,
    C XOR P = C' XOR P', where (P', C') are the modified PT/CT pair.

    @param pt [str]: Original PT
    @param ct [str]: Original CT
    @payload [str]: PT you want to insert into the string
    @offset [int]: Offset to insert the payload
    @returns [str]: CT corresponding to a PT embedded with @payload
    """

    ptnew = (pt[:offset] + payload + pt[offset+len(payload):])[:len(pt)]
    return xorstr(xorstr(pt, ct), ptnew)

if __name__=='__main__':
    oracle = SessionOracle()
    initial_str = oracle.PREFIX + 'nouserdata;name=bob' + oracle.SUFFIX
    admin_payload = ';admin=true;'

    # Print the initial string and verify that admin is not set to true
    print initial_str
    print oracle.admin_exists(initial_str)
    # Encrypt it to get the initial PT/CT pair
    initial_ct = oracle.encrypt(initial_str)
    # Using just the initial PT/CT pair, generate a CT for an admin string
    admin_ct = ctr_bitflip(initial_str, initial_ct, admin_payload)
    # Verify that admin is set to true
    print oracle.admin_exists(admin_ct)
