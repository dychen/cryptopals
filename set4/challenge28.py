"""
Implement a SHA-1 keyed MAC
---------------------------

Find a SHA-1 implementation in the language you code in.

Don't cheat. It won't work.
Do not use the SHA-1 implementation your language already provides (for
instance, don't use the "Digest" library in Ruby, or call OpenSSL; in Ruby,
you'd want a pure-Ruby SHA-1).
Write a function to authenticate a message under a secret key by using a
secret-prefix MAC, which is simply:

SHA1(key || message)
Verify that you cannot tamper with the message without breaking the MAC you've
produced, and that you can't produce a new MAC without knowing the secret key.
"""

import hashlib
from challenge25 import rand_bytes

def sha1_hash(key, msg):
    h = hashlib.sha1()
    h.update(key + msg)
    return h.hexdigest()

def tamper(key, msg, mac):
    """
    Modify one byte of the message at a time and verify the corresponding MAC
    is not the same as the original MAC.
    """
    for i, c in enumerate(msg):
        c = chr(ord(c) - 1)
        newmsg = msg[:i] + c + msg[i:]
        print newmsg, sha1_hash(key, newmsg) == mac

def reproduce(msg, mac):
    """
    Take N random keys and try to generate the original MAC.
    """
    N = 10000
    for _ in range(N):
        if sha1_hash(rand_bytes(16), msg) == mac:
            print 'Uh oh, MAC found'
            return
    print 'MAC was not found. We\'re safe!'
    return

if __name__=='__main__':
    key = 'YELLOW SUBMARINE'
    msg = 'Super secret message'
    mac = sha1_hash(key, msg)
    print 'MAC: %s' % mac
    tamper(key, msg, mac)
    reproduce(msg, mac)
