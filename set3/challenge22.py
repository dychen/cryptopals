"""
Crack an MT19937 seed
---------------------

Make sure your MT19937 accepts an integer seed value. Test it (verify that
you're getting the same sequence of outputs given a seed).

Write a routine that performs the following operation:

Wait a random number of seconds between, I don't know, 40 and 1000.
Seeds the RNG with the current Unix timestamp
Waits a random number of seconds again.
Returns the first 32 bit output of the RNG.
You get the idea. Go get coffee while it runs. Or just simulate the passage of
time, although you're missing some of the fun of this exercise if you do that.

From the 32 bit RNG output, discover the seed.
"""

import time
from challenge21 import Random

def recover_timestamp_seed(randint):
    """
    Recover a MT19937 seed from an integer seeded by a timestamp. Starting with
    the current timestamp, check previous timestamps until you find one that
    produces the same random integer. That is your seed.

    @param randint [int]: Random 32-bit integer
    @returns [int]: The seed that generated that integer
    """

    currTime = int(time.time())
    while currTime > 0:
        if Random(currTime).randint() == randint:
            return currTime
        currTime -= 1
    # We somehow failed to find the seed. Maybe it wasn't seeded by timestamp?
    return

if __name__=='__main__':
    # (Sort of but not really) random time from 0 to 30 seconds
    randsecs = Random(int(time.time() * 13791)).randint() % 30

    seed = int(time.time())
    print 'Original seed: %s' % seed
    rand = Random(seed)
    randint = rand.randint()
    print 'Simulating the passage of time...'
    time.sleep(randsecs)
    print 'Recovering...'
    print 'Recovered seed: %s' % recover_timestamp_seed(randint)
