"""
Fixed XOR
---------

Write a function that takes two equal-length buffers and produces their XOR
combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179
"""

def xor(b1, b2):
    r = hex(int(b1, 16) ^ int(b2, 16))[2:-1]
    # 0-pad the result
    if len(r) % 2 == 1:
        return '0' + r
    return r

if __name__=='__main__':
    b1 = '1c0111001f010100061a024b53535009181c'
    b2 = '686974207468652062756c6c277320657965'
    print xor(b1, b2)
