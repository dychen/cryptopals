# cryptopals
Solutions to challenges posted at http://cryptopals.com/. I use the Python ```cryptography``` library for the implementation of cryptographic primitives. More information can be found here: https://cryptography.io/.

Notes:

1. **Hex to base 64:**
2. **XOR two hex strings:**
3. **Decrypt single character XOR:** The string scoring function is useful later on.
4. **Find the string that's been encrypted with single character XOR:**
5. **Implement the Vigenere cipher:**
6. **Decrypt the Vigenere cipher:** I used my own implementation here instead of the recommended implementation (no Hamming distance).
7. **Implement AES with ECB:** I used the Python ```cryptography``` library for the AES primitive.
8. **Detect CTs encrypted with AES/ECB:**
9. **Implement PKCS#7 padding:** Ran into a major bug here that messed up future problems. I initially didn't pad block-aligned words (instead, you're supposed to pad them with another block).
10. **Implement AES with CBC:** Implemented this with AES/ECB. Initially, I called the function I wrote in problem 7, which was a mistake because it PKCS-pads every block, doubling the block size.
11. **Detect ECB vs CBC:** The underlying assumption I made is ECB repeats blocks whereas CBC doesn't. A stronger assumption is that if blocks don't repeat, the encryption mode is CBC (true in this case, false in basically any other situation).
12. **ECB discover hidden padding:** The first interesting problem. Initially, I spent a lot of time writing a working recursive solution because I was only comparing the next unknown byte to the message byte (and multiple characters could work in this case). This is unnecessary if you compare all known bytes plus the next unknown byte.
13. **ECB cut-and-paste:** (Unfinished) I didn't understand this question. What can the attacker do (and what can't he do)?
14. **ECB discover hidden padding with prefix:** Easily reduces to problem 12 once you find the prefix length.
15. **PKCS#7 padding validation:**
16. **CBC bit-flipping:** The first challenge where you take advantage of the underlying cipher construction.
17. **CBC padding oracle attack:** Sometimes the last block doesn't decrypt correctly and I haven't figured out why.
18. **Implement AES with CTR**: Took me a while because I didn't read about the keystream construction. I just assumed it was ```nonce ^ ctr``` or ```(nonce + ctr) % nonce```.
19. **Break CTR with nonce reuse**: Not sure what the author was going for here. My solution involves guessing ```E_k(keystream)``` and using that to decrypt the CTs.
20. **Break CTR with nonce reuse v2**: Not sure what the author was going for here either. This time I just solved for the longest PT and used that to decrypt the other PT. Basically the same as 19 except a little more complicated.
21. **Implement MT19937**: Had to read (sections of) a paper for this. If you want to understand the periodicity, equity of distribution, and parameters, you definitely need to know a bit of math. I used the seed generation function described in the appendix of the paper.
