'''
---PROGRAM DESCRIPTION---
Digital signature scheme based on RSA
(encryption portion)

Creates a signature.txt file in same directory containing the public keys
(overwrites same file on subsequent executions with new generated keys)

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

-------------------------
'''

import sys, random, hashlib

BLOCK_SIZE = 4096

def sign(msg):
    '''Creates signature.txt file and writes public keys to it

    Args:
        msg (str): location of file containing information
    '''
    hashInt = hashFile(msg)
    primes = generatePrimes()
    encryptedKey = generateSignKey(primes[0], primes[1])
    
    n = primes[0] * primes[1]
    encryptedMsg = pow(hashInt, int(encryptedKey), n)

    f = open("sign.txt", 'w')
    f.write(str(encryptedMsg))
    f.write("\n")
    f.write(str(n))
    f.close()

### --------------------------------------------------------------------------
###  helper functions
### --------------------------------------------------------------------------

def generateSignKey(p, q):
    '''Returns a secret RSA based signing int key

    Args:
        p (int): first prime number
        q (int): second prime number
    '''
    euler = (p-1)*(q-1)
    k = 1
    d = 1.1 # dummy INIT value

    while not(d.is_integer()):
        # NOTE: hardcoded public key e = 65537 (2**16+1)
        e = 65537
        d = ((k*euler)+1)/(e)
        k += 1
    return d

def generatePrimes():
    '''Returns two random 3-digit primes as tuple (p, q)'''
    primes = [101, 103, 107, 109, 113, 
    127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 
    199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 
    283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 379, 
    383, 389, 397, 401, 409, 419, 421, 431, 433, 439, 443, 449, 457, 461, 463, 
    467, 479, 487, 491, 499, 503, 509, 521, 523, 541, 547, 557, 563, 569, 571, 
    577, 587, 593, 599, 601, 607, 613, 617, 619, 631, 641, 643, 647, 653, 659, 
    661, 673, 677, 683, 691, 701, 709, 719, 727, 733, 739, 743, 751, 757, 761, 
    769, 773, 787, 797, 809, 811, 821, 823, 827, 829, 839, 853, 857, 859, 863, 
    877, 881, 883, 887, 907, 911, 919, 929, 937, 941, 947, 953, 967, 971, 977, 
    983, 991, 997]
    r1 = random.randint(0, 142)
    r2 = random.randint(0, 142)
    return(primes[r1], primes[r2])

def hashFile(file):
    '''Returns hash (int) of a given file

    Args:
        file (str): location of file to be hashed
    '''
    file_hash = hashlib.sha256()
    with open(file, 'rb') as f:
        fb = f.read(BLOCK_SIZE)
        while len(fb) > 0:
            file_hash.update(fb)
            fb = f.read(BLOCK_SIZE)
    hexHash = file_hash.hexdigest()
    return int(hexHash, 16)

if __name__ == "__main__":
    if(len(sys.argv) != 2):
        print("Usage: python3 rsaSign.py file")
        exit(0)

    sign(sys.argv[1])
