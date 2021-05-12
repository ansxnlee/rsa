# rsa 

This is an education implemenetation of RSA that should ABSOLUTELY NOT be used for security.

Signing usage: python3 rsaSign.py file
Verification usage: python3 rsaVerify.py file sign

Where 'file' is the path to some file 
and 'sign' is the path to a text file that contains the appropriate digital keys



---Possible Improvements---

-find a better way of generating large primes
-add support for different file types?
-abstract sign.txt data to make it not obvious in what they represent
-find ways of protecting against different attacks
(i.e. chosen plaintext, "blinded signature" scheme)

---Future Design Tips---

-primes p,q must be at least 512 bits (2**9)
-"p-1" and "q-1" should have large prime factors
-gcd(p-1, q-1) should not be too large
-modulo 'n' should be at least 1024 bits (2**10)
-private key 'd' shouldn't be smaller than n**(1/4)
