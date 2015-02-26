"""
Implement the MT19937 Mersenne Twister RNG
------------------------------------------

You can get the psuedocode for this from Wikipedia.

If you're writing in Python, Ruby, or (gah) PHP, your language is probably
already giving you MT19937 as "rand()"; don't use rand(). Write the RNG
yourself.
"""

"""
Link to the original paper:
http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/ARTICLES/mt.pdf
Unsurprisingly, the paper does a much better job of explaining the algorithm
than the corresponding Wikipedia article.
"""

class Random():
    """
    Generates a 32-bit pseudorandom number (randint()). It can also generate a
    32-bit pseudorandom double (rand()). First, initialize the generator with
    a seed. Successive calls to rand() or randint() will be pseudorandom from
    that seed.
    """

    # Constants:

    # For seed generation:
    __default = 4357             # Default seed
    __genm = int('ffffffff', 16) # Generation bitmask
    __genp = 69069               # Generation multiplier

    # For the recurrence:
    __w = 32  # Word size
    __n = 624 # Number of words in the word vector (degree of recurrence)
    __m = 397 # Offset of previously comparable word vector
    __r = 31  # Number of bits of the lower bitmask
    __umask = int(hex(2 ** __r)[2:], 16)     # Upper bitmask
    __lmask = int(hex(2 ** __r - 1)[2:], 16) # Lower bitmask
    __a = int('9908b0df', 16) # Coefficients of the last row in vector matrix A

    # For the tempering transform:
    __b = int('9d2c5680', 16) # Tempering bitmask
    __c = int('efc60000', 16) # Tempering bitmask
    __u = 11 # First tempering bitshift
    __s = 7  # Tempering bitshift
    __t = 15 # Tempering bitshift
    __l = 18 # Last tempering bitshift

    # State:
    __mt = [0] * __n # The (n_w)-byte state vector (n vectors of w bytes)
    __i = 0          # The index of the state vector

    def __init__(self, seed=__default):
        """
        Implemented as described in the paper (Appendix C), which references a
        generator in Knuth (AoCP) vol. 2, pp. 102:
            mt[0] = seed & 0xffffffff
            mt[i] = (69069 * mt[i-1]) & 0xffffffff
        NOTE: The seed MUST be nonzero

        @param seed [int]: Expects a 32-bit integer. The bitmask 0xffffffff
                           truncates the input to 32 bits.
        """

        seed = self.__default if seed == 0 else seed
        self.__mt[0] = seed & self.__genm
        for i in range(1, self.__n):
            self.__mt[i] = (self.__genp * self.__mt[i-1]) & self.__genm

    def __generate(self):
        """
        Implemented as described in the paper (section 2):

        Constants:
            w (word size) := 32 (bits)
            n (number of words in the word vector x) := 624
            m (offset from past word vector) := 397
            r (number of bits in lower bitmask) := 31
            A (transformation matrix) :=
                1  1  ...  1
                .  .       .  such that xA := x >> 1,       x_0 = 0, x_0 is lsb
                .  .       .            xA := (x >> 1) ^ a, x_0 = 1
                1  1       1  where a = (a_w-1, a_w-2, ..., a_0)
                a_w-1 ... a_0       x = (x_w-1, x_w-2, ..., x_0)
                              for a single 32-bit word vector x
            b, c := w-bit bitmasks in the tempering transform
            u, s, t, l := bitshifts in the tempering transform

        Given the constants above, the steps are as follows:
            1. Start with an initial seed x_0, ..., x_n-1, where x_i are word
               vectors (generated in __init__()).
            2. Generate the next word vectors x_n, x_n+1, ... by applying the
               following recurrence:
                x_k+n = x_k+m ^ (x^u_k | x^l_k+1) A, k = 0, 1, ...
                Where x_k+n is the next word vector
                      x_k+m is the (n-m)th previous word vector
                      x^u_k is the upper w-r bits of x_k
                      x^l_k+1 is the lower r bits of x_k+1
                      A is some constant w x w matrix
                      ^ is XOR
                      | is effectively string concatenation (ORing masked bits)
            3. Apply the following tempering transform to the state vector x:
                x -> y = xT:
                1. y := x ^ (x >> u)
                2. y := y ^ ((y << s) & b)
                3. y := y ^ ((y << t) & c)
                4. y := y ^ (y >> l)
            4. Return y

        Note: Notationally, what is described here as x is the list mt in the
              code.

        @returns [int]: Pseudorandom 32-bit integer
        """

        # Recurrence
        mid = ((self.__mt[self.__i] & self.__umask) # (x^u_k | x^l_k+1)
               | (self.__mt[(self.__i + 1) % self.__n] & self.__lmask))
        a = 0 if int('00000001', 16) & mid == 0 else self.__a
        self.__mt[self.__i] = (self.__mt[(self.__i + self.__m) % self.__n]
                               ^ (mid >> 1) ^ a)

        # Tempering function
        y = self.__mt[self.__i]
        y ^= y >> self.__u
        y ^= (y << self.__s) & self.__b
        y ^= (y << self.__t) & self.__c
        y ^= y >> self.__l

        self.__i += 1
        self.__i %= self.__n
        return y

    def rand(self):
        """
        @returns [float]: Pseudorandom 32-bit float
        """

        return float(self.__generate()) / int('ffffffff', 16)

    def randint(self):
        """
        @returns [int]: Pseudorandom 32-bit integer
        """

        return self.__generate()

if __name__=='__main__':
    seed = int(raw_input('Enter a seed value: '))
    rand = Random(seed)
    for _ in range(10):
        print rand.rand()
        print rand.randint()
