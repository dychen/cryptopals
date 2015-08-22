"""
Re-implementation of the base64 encode/decode functions. This is meant purely
as a learning exercise and is by no means performant.
"""

class B64:
    __CHARS = \
        'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

    @classmethod
    def b64encode(cls, s):
        """
        1. Right-pad the string with the null byte \0 to a multiple of 3
        2. For every block of three 8-bit characters in the string, concatenate
           them into a single 24-bit integer, separate them into four 6-bit
           numbers, and use these to index the __CHARS string and generate the
           corresponding 4 digits.
        3. Every 76 output characters (every 19 blocks of 3 or every 57 input
           characters, append a newline) in accord to the MIME specs
           (https://en.wikipedia.org/wiki/Base64#MIME)
        3. Remove the zero-pad characters and replace them with '='s
        """

        arrout = []

        padlen = (3 - len(s) % 3) % 3 # The extra % 3 to 0
        sarr = [c for c in s] + ['\0'] * padlen

        for i in range(0, len(sarr), 3):
            if i % 57 == 0 and i > 0:
                arrout += '\n'
            mapped = sum([ord(x) * 2 ** (8 * (2-n))
                          for n, x in enumerate(sarr[i:i+3])])
            mapblock = [cls.__CHARS[mapped >> ((3 - n) * 6) & 63]
                        for n in range(4)]
            arrout += mapblock

        return ''.join(arrout[:-padlen] + ['='] * padlen)

    @classmethod
    def b64decode(cls, s):
        return

if __name__=='__main__':
    print B64.b64encode('Make sure you hit \'em with a prenup. Then tell that '
                        'man to ease up.')
    #print B64.b64decode('TWFrZSBzdXJlIHlvdSBoaXQgJ2VtIHdpdGggYSBwcmVudXAuIFRoZ'
    #                    'W4gdGVsbCB0aGF0IG1hbiB0\nbyBlYXNlIHVwLg==')
