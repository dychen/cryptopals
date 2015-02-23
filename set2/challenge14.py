"""
Byte-at-a-time ECB decryption (Harder)
--------------------------------------

Take your oracle function from #12. Now generate a random count of random bytes
and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that
obstacle? The hint is: you're using all the tools you already have; no crazy
math is required.

Think "STIMULUS" and "RESPONSE".
"""

from challenge10 import b642hex, aes_ecb_encrypt
from challenge11 import rand_bytes, rand_bytes_range

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
        self.__randprefix = rand_bytes_range(0, 255) # Add to the front of
                                                     # every PT

    def encrypt(self, pt):
        """
        Returns E_k(randprefix || pt || SECRET_STRING) where E_k is AES 128 in
        ECB mode and || is the concatenation operator. The same key k is used
        for the entire session.

        @param pt [str]: ASCII PT
        @returns [str]: ASCII CT
        """

        padded_pt = (self.__randprefix + pt
                     + b642hex(self.__SECRET_STRING).decode('hex'))
        return aes_ecb_encrypt(self.__key, padded_pt)

def decrypt_session_secret():

    def get_blocksize():
        """
        Returns the blocksize of the oracle. Continually add one byte of
        padding until the size of the returned CT changes. The difference in
        the CT lengths is the blocksize.

        @returns [int]: Blocksize of the ECB mode cipher.
        """

        paddedlen = len(oracle.encrypt(''))
        padbytes = 0
        while len(oracle.encrypt('A' * padbytes)) == paddedlen:
            padbytes += 1
        return len(oracle.encrypt('A' * padbytes)) - paddedlen

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

    def get_prefix_offset():
        """
        Finds the amount of padding the input PT must be offset by by
        continually adding one byte of padding and calling the oracle until a
        repetition is produced. Returns the number of padding bytes that must
        be added and the starting index of the block-aligned message.

        @returns [tuple]: ([int], [int]), where t[0] is the length of padding
                          that must be prepended to block-align the message and
                          t[1] is the index of the beginning of the message
                          with that padding.
        """

        def block_repetition(s):
            """
            Returns True if there is a block reptition in a string:
            |A...A|B...B|...|R...R|R...R|S...S|, the block |R...R| is repeated.

            @returns [tuple]: ([bool], [int]), Returns (True, i) where i is the
                              index of the first character of the block
                              following the repetition if a repetition is
                              found. Returns (False, -1) otherwise.
            """

            for i in range(0, len(s)-blocksize, blocksize):
                if s[i:i+blocksize] == s[i+blocksize:i+2*blocksize]:
                    return (True, i + 2*blocksize)
            return (False, -1)

        padlen = 0
        repetition, index = block_repetition(oracle.encrypt('A' * padlen))
        while not repetition:
            padlen += 1
            repetition, index = block_repetition(oracle.encrypt('A' * padlen))
        return (padlen, index)

    def get_msg_length():
        """
        This is slightly more complicated than the same function in challenge
        12 but the idea is the same. Keep adding padding bytes until the CT
        length changes. This is the length of padding added to the PT. Subtract
        that from the length of the returned CT. In this case, we start with a
        padded, block-aligned message:
        |R...R| ... |RRRPPPPP|PPPPPPPP|PPPPPPPP|M...M|MMMppppp| where p are
        padding bytes. We want to find the number of p. So, add Q:
        |R...R| ... |RRRPPPPP|PPPPPPPP|PPPPPPPP|QQQQQQMM|M...M|MMMMMMMM|M
        until the size of the CT changes. The number of p in the original
        message is equal to the number of extra padding bytes |Q| - 1. The
        length of the message is given by:
        |msg| - (|R| + |P|) - (|Q| - 1)

        @returns [int]: The length of the secret message.
        """

        paddedlen = len(oracle.encrypt('A' * pad_prefixlen))
        for i in range(1, blocksize+1): # 1 pad is required where msglen %
                                        # blocksize is 0
                                        # blocksize pads are required where
                                        # msglen % blocksize is 1
            if paddedlen != len(oracle.encrypt('A' * (pad_prefixlen + i))):
                return paddedlen - msg_offset - (i - 1)

    def next_byte(padlen, blockidx, msg):
        """
        See the name function in challenge 12 for better documentation. The two
        differences are:
            1. Offset the oracle input by an addition prefix padding (found
               previously) to block-align the message.
            2. Offset the comparison indices to start at the index of the
               first character of the block-aligned message.

        @param padlen [int]: Length of the payload. This needs to be offset by
                             the number of bytes of extra padding required to
                             block-align the message.
        @param blockidx [int]: The block of the message the target byte is in.
                               This needs to be offset by the blocks taking up
                               by the prefix and extra padding.
        @param msg [str]: Current known message.
        @returns [list]: List of possible ASCII characters that the next
                         character in the message could be.
        """

        blockcmp = blocksize * (blockidx + 1)
        target_msg = oracle.encrypt('A' * (pad_prefixlen + padlen))
        ct_mapping = [oracle.encrypt('A' * (pad_prefixlen + padlen) + msg + c)
                      for c in map(chr, range(0, 255))]
        next_byte = [chr(i) for i, ct in enumerate(ct_mapping)
                     if (ct[msg_offset:msg_offset+blockcmp]
                         == target_msg[msg_offset:msg_offset+blockcmp])][0]
        return next_byte

    def decode():
        """
        Strategy:
            Suppose the oracle has the following message PT (blocksize of 8).
            R...R| ... |RRRMMMMM| ... | M...M
            We want to continually add bytes of padding until this happens:
            R...R| ... |RRRPPPPP|PPPPPPPP|PPPPPPPP|M...M
            We detect when this happens as the smallest length of padding P
            such that there is a repitition among blocks. Then, the problem
            reduces the problem solved in challenge 12 with two caveats:
                1. The current block index blockidx is offset by the index of
                   the block immediately following the repeated blocks.
                2. In all calls to the oracle, you must prepend an extra |P|
                   bytes to the PT, where |P| is the length of the smallest
                   padding P required to cause a repetition.
        """

        msg = ''
        padlen = blocksize - 1
        blockidx = 0
        while len(msg) < msglen:
            if padlen == 0:
                padlen = blocksize
                blockidx += 1
            msg += next_byte(padlen, blockidx, msg)
            padlen -= 1
        return msg

    oracle = SessionOracle()
    blocksize = get_blocksize()
    pad_prefixlen, msg_offset = get_prefix_offset()
    msglen = get_msg_length()
    return decode()

if __name__=='__main__':
    print decrypt_session_secret()
