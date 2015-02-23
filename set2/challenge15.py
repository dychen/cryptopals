"""
PKCS#7 padding validation
-------------------------

Write a function that takes a plaintext, determines if it has valid PKCS#7
padding, and strips the padding off.

The string:

"ICE ICE BABY\x04\x04\x04\x04"

... has valid padding, and produces the result "ICE ICE BABY".

The string:

"ICE ICE BABY\x05\x05\x05\x05"

... does not have valid padding, nor does:

"ICE ICE BABY\x01\x02\x03\x04"

If you are writing in a language with exceptions, like Python or Ruby, make
your function throw an exception on bad padding.

Crypto nerds know where we're going with this. Bear with us.
"""

def valid_pkcs7_padding(s):
    """
    Determine if a string has valid PKCS#7 padding. Do this by examining the
    last N bytes where N is the ordinal of the last byte of the input and make
    sure that the last N bytes are N

    @param s [str]: Input string
    @returns [bool]: True if the string is correctly padded and False otherwise
    """

    last = ord(s[-1])
    if len(set(map(ord, s[-last:]))) == 1:
        return True
    else:
        raise Exception('Not a valid PKCS#7 encoding for string %s' % s)

if __name__=='__main__':
    print valid_pkcs7_padding("ICE ICE BABY\x04\x04\x04\x04")
    print valid_pkcs7_padding("ICE ICE BABY\x05\x05\x05\x05")
    print valid_pkcs7_padding("ICE ICE BABY\x01\x02\x03\x04")
