"""
ECB cut-and-paste
-----------------

Write a k=v parsing routine, as if for a structured cookie. The routine should
take:

foo=bar&baz=qux&zap=zazzle

... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}

(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email
address. You should have something like:

profile_for("foo@bar.com")

... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}

... encoded as:

email=foo@bar.com&uid=10&role=user

Your "profile_for" function should not allow encoding metacharacters (& and =).
Eat them, quote them, whatever you want to do, but don't let people set their
email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

A. Encrypt the encoded user profile under the key; "provide" that to the
"attacker".
B. Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid"
ciphertexts) and the ciphertexts themselves, make a role=admin profile.
"""

from challenge10 import aes_ecb_encrypt, aes_ecb_decrypt
from challenge11 import rand_bytes

class SessionOracle:
    """
    Encrypts input PTs with AES 128 in ECB mode using a session key.
    """

    def __init__(self):
        self.__key = rand_bytes(16) # Establish a random 16-byte key for the
                                    # length of this "session"

    def encrypt(self, pt):
        return aes_ecb_encrypt(self.__key, pt)

    def decrypt(self, ct):
        return aes_ecb_decrypt(self.__key, ct)

def paramstr_to_obj(paramstr):
    obj = {}
    for param in paramstr.split('&'):
        k, v = param.split('=')
        obj[k] = v
    return obj

def profile_for(email):
    obj = {
        'email': email,
        'uid': 10,
        'role': 'user'
    }
    return '&'.join(['%s=%s' % (k, v) for k, v in obj.iteritems()])

def make_user_admin(email):
    """
    Construct the modified encrypted CT corresponding to the url encoded
    paramstr email=[email]&uid=10&role=admin using only calls to the oracle
    (calls to aes_ecb_encrypt with the same session key).

    @param email [str]: The email used to generate the url encoded string
                  email=[email]&uid=10&role=user
    @returns [str]: An encrypted CT that when decrypted returns the url encoded
                    string email=[email]&uid=10&role=admin
    """

    def get_blocksize(maxlen=1024):
        """
        Returns the blocksize of the oracle. Continually add one byte of
        padding until, for an input message of length M, the first M/2 bytes of
        the output message are equal to the second M/2 bytes. This also checks
        that the oracle is using ECB mode. If no repetition is found up to a
        large maximum length, then assume that ECB mode is not being used.

        @returns [int]: Blocksize of the ECB mode cipher or False if no
                        blocksize is found (this implies that ECB mode is not
                        set).
        """

        paddedlen = len(oracle.encrypt(''))
        padbytes = 1
        while (oracle.encrypt('A' * padbytes)[:padbytes/2]
               != oracle.encrypt('A' * padbytes)[padbytes/2:padbytes]):
            if padbytes > maxlen:
                return False
            padbytes += 1
        return padbytes / 2

    oracle = SessionOracle()
    # Make sure it's working
    encrypted_profile = oracle.encrypt(profile_for(email))
    decrypted_profile = oracle.decrypt(encrypted_profile)
    print encrypted_profile.encode('hex')
    print decrypted_profile

    # Now, only using @email and @encrypted_profile, make a role=admin profile.
    blocksize = get_blocksize()
    return

if __name__=='__main__':
    make_user_admin('foo@bar.com')
