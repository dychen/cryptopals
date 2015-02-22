"""
Byte-at-a-time ECB decryption (Simple)
--------------------------------------

Copy your oracle function to a new function that encrypts buffers under ECB
mode using a consistent but unknown key (for instance, assign a single random
key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE
ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK

Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string
by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated calls to the
oracle function!

Here's roughly how:

1. Feed identical bytes of your-string to the function 1 at a time --- start
with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of
the cipher. You know it, but do this step anyway.
2. Detect that the function is using ECB. You already know, but do this step
anyways.
3. Knowing the block size, craft an input block that is exactly 1 byte short
(for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what
the oracle function is going to put in that last byte position.
4. Make a dictionary of every possible last byte by feeding different strings
to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering
the first block of each invocation.
5. Match the output of the one-byte-short input to one of the entries in your
dictionary. You've now discovered the first byte of unknown-string.
6. Repeat for the next byte.

Congratulations.
This is the first challenge we've given you whose solution will break real
crypto. Lots of people know that when you encrypt something in ECB mode, you
can see penguins through it. Not so many of them can decrypt the contents of
those ciphertexts, and now you can. If our experience is any guideline, this
attack will get you code execution in security tests about once a year.
"""

from challenge10 import b642hex, aes_ecb_encrypt
from challenge11 import rand_bytes

def is_ascii(char):
    """
    @param char [str]: ASCII character
    @returns True if @char is a valid ASCII character and False otherwise
    """
    return ord(char) not in set([128] + [153] + range(161, 255) + range(0, 9) +
                                range(11, 32) + [127] + range(129, 153) +
                                range(154, 161))

class SessionOracle:
    """
    Encrypts input PTs with AES 128 in ECB mode using a session key and padding
    the PT with a secret string. Our goal is to figure out the secret string
    with repeated calls to the oracle.
    """

    __SECRET_STRING = (
        'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg'
        'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq'
        'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg'
        'YnkK'
    )

    def __init__(self):
        self.__key = rand_bytes(16) # Establish a random 16-byte key for the
                                    # length of this "session"

    def encrypt(self, pt):
        """
        Returns E_k(pt || SECRET_STRING) where E_k is AES 128 in ECB mode and
        || is the concatenation operator. The same key k is used for the entire
        session.

        @param pt [str]: ASCII PT
        @returns [str]: ASCII CT
        """

        iv = rand_bytes(16)
        padded_pt = pt + b642hex(self.__SECRET_STRING).decode('hex')
        return aes_ecb_encrypt(self.__key, padded_pt)

def decrypt_session_secret():
    """
    Decrypt an AES 128 ECB mode oracle with a session key and PKCS#7 padding
    with the following steps:
        1. Find out the blocksize and make sure the oracle is in ECB mode.
           (see get_blocksize())
        2. Get the unpadded length of the session message.
           (see get_msg_length())
        3. Decode the session message by checking payload messages of the form
           P || M || Y where P is a prefix of the desired length, M is the
           first |M| known bytes of the message, and Y is the character we
           think might be the next character of the message. We check this
           against the results of sending the payload P at the index of Y. If
           the bytes match, we might have found a hit. Since multiple bytes can
           match here, we use a recursive strategy to find the entire string.
           (see decode())
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

    def get_msg_length():
        """
        Returns the non-padded length of the secret message. The way to do this
        is to find the length of the padded message and subtract the number of
        bytes of padding. The number of bytes of padding can be found by
        continually adding one byte of padding until the length of the returned
        message changes (it will increase by blocksize).

        @returns [int]: Non-padded length of the secret message.
        """

        paddedlen = len(oracle.encrypt(''))
        for i in range(1, blocksize+1): # 1 pad is required where msglen %
                                        # blocksize is 0
                                        # blocksize pads are required where
                                        # msglen % blocksize is 1
            if paddedlen != len(oracle.encrypt('A' * i)):
                return paddedlen - i + 1

    def next_byte(padlen, blockidx, msg):
        """
        Sends the following payloads to the oracle:
            'A'*@padlen || @msg || Y, where Y is a char from 0x00 to 0xff
            'A'*@padlen, the target payload
        Assuming @msg is correct (is equal to the first |@msg| bytes of the
        secret message), the first |'A'*@padlen| + |@msg| bytes of all payloads
        (including the target payload) should be the same, and the next byte
        should be compared. Note that |'A'*@padlen| + |@msg| + 1 should be a
        multiple of the blocksize because we want to check the equality of full
        blocks. The next character is the Y where the CT of the first
        |'A'*@padlen| + |@msg| + 1 bytes are equal to the same first bytes of
        CT from the target payload. Since each PT uniquely maps to a CT, there
        can only be one correct Y. And there must be at least one correct Y
        because the domain of Y spans the set of all possible characters.
        Return this set (filtered for valid ASCII characters).

        @param padlen [int]: Length of the payload
        @param blockidx [int]: The block the target byte is in.
        @param msg [str]: Current known message.
        @returns [list]: List of possible ASCII characters that the next
                         character in the message could be.
        """

        payload_prefix = 'A' * padlen
        blockcmp = blocksize * (blockidx + 1)
        # Mapping of { ptbyte: ct[:blockcmp] } for all pt bytes [int] in
        # (0, 255).
        ct_mapping = [oracle.encrypt(payload_prefix + msg + chr(c))[:blockcmp]
                      for c in range(256)]
        target_str = oracle.encrypt(payload_prefix)[:blockcmp]
        possibilities = [chr(i) for i, ctprefix in enumerate(ct_mapping)
                         if ctprefix == target_str][0] # Should always be
                                                       # of length 1
        return possibilities

    def decode():
        """
        Decodes the secret message by finding successive bytes of the message
        blockwise. To find the first byte, the padding starts at blocksize - 1
        and decreases until the first entire block is found. Then the process
        repeats for successive blocks until the entire message is found.

        @returns [str]: The decoded oracle secret message.
        """

        msg = ''
        padlen = blocksize - 1
        blockidx = 0
        while len(msg) < msglen:
            if padlen == 0:
                padlen = 16
                blockidx += 1
            msg += next_byte(padlen, blockidx, msg)
            padlen -= 1
        return msg

    oracle = SessionOracle()
    blocksize = get_blocksize()
    msglen = get_msg_length()
    return decode()

if __name__=='__main__':
    print decrypt_session_secret()
