"""
Detect AES in ECB mode
----------------------

In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic;
the same 16 byte plaintext block will always produce the same 16 byte
ciphertext.
"""

def detect_ebc(txt):
    """
    @param txt [str]: CT (hex string)
    @returns [bool]: True if the CT was encrypted using ECB, False otherwise.
    """

    chunks = [txt[i:i+16*2] for i in range(0, len(txt), 16*2)]
    return not (len(set(chunks)) == len(chunks))

if __name__=='__main__':
    with open('challenge8.txt', 'r') as f:
        txts = [line.strip() for line in f]
    for txt in txts:
        if detect_ebc(txt):
            print txt
