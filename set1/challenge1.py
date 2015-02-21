"""
Convert hex to base64
---------------------

The string:

49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573\
206d757368726f6f6d

Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
So go ahead and make that happen. You'll need to use this code for the rest of
the exercises.
"""

import binascii

def hex2b64(s):
    return binascii.b2a_base64(binascii.unhexlify(s))

if __name__=='__main__':
    s = ('49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f6973'
         '6f6e6f7573206d757368726f6f6d')
    print hex2b64(s)
