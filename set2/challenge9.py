"""
Implement PKCS#7 padding
------------------------

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of
plaintext into ciphertext. But we almost never want to transform a single
block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a
plaintext that is an even multiple of the blocksize. The most popular padding
scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes
of padding to the end of the block. For instance,

"YELLOW SUBMARINE"
... padded to 20 bytes would be:

"YELLOW SUBMARINE\x04\x04\x04\x04"
"""

"""
PKCS#7 padding is described in RFC 5652 section 6.3, which can be found here:
    http://tools.ietf.org/html/rfc5652#section-6.3
In particular:
    "For such algorithms, the input shall be padded at the trailing end with
     k-(lth mod k) octets all having value k-(lth mod k), where lth is the
     length of the input. In other words, the input is padded at the trailing
     end with one of the following strings:

                     01 -- if lth mod k = k-1
                  02 02 -- if lth mod k = k-2
                      .
                      .
                      .
            k k ... k k -- if lth mod k = 0"
"""

def pkcs7_pad(s, length):
    """
    Returns a PKCS#7-padded string of length @length. It pads a string to the
    nearest multiple of @length (rounded up) with each padded byte having the
    value equal to the total number of padded bytes added.

    @param s [str]: Input ASCII string
    @param length [int]: Desired length of padded string
    @returns [str]: Padded string
    """

    pad = length - len(s) % length
    return s + chr(pad) * pad

if __name__=='__main__':
    padded_msg = pkcs7_pad('YELLOW SUBMARINE', 20)
    print len(padded_msg), padded_msg, padded_msg.encode('hex')
