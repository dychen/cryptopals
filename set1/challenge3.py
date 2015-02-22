"""
Single-byte XOR cipher
----------------------

The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the
message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character
frequency is a good metric. Evaluate each output and choose the one with the
best score.
"""

def score(s):
    """
    Returns the likelihood that a string is a valid PT string.

    @param s [str]: CT string.
    @return [int]: Number (-inf, +inf), where more positive means greater
                   likelihood that the CT is a string.
    """
    def charscore(c):
        """
        Naively returns the score of a character (representing the likelihood
        that the character implies a valid PT string).
        """
        # +1 if string is in the set of characters or spaces
        positive_set = set(range(ord('a'), ord('a')+26) + [ord(' ')])
        # -1 if the string is in the set of rarely used characters:
        #   128, 153, 161-255
        negative_set = set([128] + [153] + range(161, 255))
        # -99 if the string is in the set of unused characters:
        #   0-8, 11-31, 127, 129-152, 154-160
        unused_set = set(range(0, 9) + range(11, 32) + [127] + range(129, 153)
                         + range(154, 161))
        if ord(c) in positive_set:
            return 1
        elif ord(c) in negative_set:
            return -9
        elif ord(c) in unused_set:
            return -99
        else:
            return 0

    return sum(map(charscore, [_ for _ in s]))

def decrypt(s):
    """
    Decrypts an input ciphertext. Assumes the encryption function D(k, s) has:
    - D: XOR
    - k: A string where len(k) == len(s) and k[i] == k[i+1] for all i in
         (0, len(k)-1)
    - s: The input ciphertext

    @param s [str]: The input ciphertext (hex string)
    @returns [str]: The decrypted plaintext
    """
    def try_key(charkey):
        """
        @param charkey [int]: Number betwen 0 and 255. Key to try against a
                              character in the CT string.
        @returns [list]: List of tuples [([int], [str]), ...], where t[0] is
                         the score (likelihood the string is correct) and t[1]
                         is the decrypted string using the input character key.
        """
        def keyxor(b):
            return chr(charkey ^ int(b, 16))

        attempt = map(keyxor, [s[i:i+2] for i in range(0, len(s), 2)])
        return (score(''.join(attempt)), ''.join(attempt))

    attempts = map(try_key, range(0, 256))
    return sorted(attempts, key=lambda x: x[0], reverse=True)[0][1]

if __name__=='__main__':
    s = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
    print decrypt(s)
