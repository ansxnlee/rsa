'''
---PROGRAM DESCRIPTION---
Digital signature scheme based on RSA
(decryption portion)

Checks both file and signature.txt to verify that the file has not been
tampered with and that the signature came from it's source
-------------------------
'''

import sys, hashlib

BLOCK_SIZE = 4096

def verify(msg, sign):
    '''Checks file integrity and autheticity of signature

    Args:
        msg (str): file location
        sign (str): signature.txt file location
    '''
    hashInt = hashFile(msg)

    f = open(sign, "r")
    encryptedMsg = f.readline()
    modulo = f.readline()

    # NOTE: hardcoded public key e = 65537 (2**16+1)
    e = 65537
    m = pow(int(encryptedMsg), e, int(modulo))
    h = pow(hashInt, 1, int(modulo))

    if(m == h):
        print("NOTICE: FILE AUTHENTICATED")
    else:
        print("NOTICE: FILE INTEGRITY COMPROMISED")

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
    if(len(sys.argv) != 3):
        print("Usage: python3 rsaVerify.py file sign")
        exit(0)

    verify(sys.argv[1], sys.argv[2])
