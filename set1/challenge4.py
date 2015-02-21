"""
Detect single-character XOR
---------------------------

One of the 60-character strings in this file has been encrypted by
single-character XOR.

Find it.

(Your code from #3 should help.)
"""

from multiprocessing import Pool
from challenge3 import decrypt, score

def work(s):
    pt = decrypt(s)
    return (score(pt), pt)

def parallel_decrypt(s):
    p = Pool(100)
    return p.map(work, s)

if __name__=='__main__':
    filename = 'challenge4.txt'
    with open(filename, 'r') as f:
        txt = [line.strip() for line in f]
    results = parallel_decrypt(txt)
    print sorted(results, key=lambda x: x[0], reverse=True)[0][1]
