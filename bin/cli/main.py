#!/usr/bin/env python
import bcrypt
from des import DesKey

def encryptAlg(password):
    # DES 8 bit
    key = DesKey(b"A quick brown fox jumped")
    # password should be length div by 8, 16
    return key.encrypt(password, padding=True)

def hashPsw(password):
    encryptedStr = encryptAlg(password)
    return bcrypt.hashpw(encryptedStr, bcrypt.gensalt(12))

def check_password(password, hashed):
    return bcrypt.checkpw(password, hashed)

def comp(psw1, psw2):
    print( "[COMP] psw1 = %s, psw2 = %s" % (psw1, psw2));
    hash1 = hashPsw(psw1)
    psw2 = encryptAlg(psw2)
    if check_password(psw2, hash1):
        print( "[COMP] true");
    else:
        print( "[COMP] false");

def printPsw(password):
    print( "[INPUT] %s" % password);
    print( "[OUTPUT] %s" % hashPsw(password));

def main():
    psw1 = b'pass123'; # b turns this string into a byte array
    psw2 = b'123pass';
    printPsw(psw1)
    printPsw(psw2)
    comp(psw1, psw1)
    comp(psw1, psw2)

if __name__ == '__main__':
    main()
