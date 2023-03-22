#!/usr/bin/env python3
import sys
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom

import hashlib

# AES key
KEY = urandom(16)

# Use a static key for testing
#KEY = b'AAAAAAAABBBBBBBB'

def encrypt_AES(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = b'\x00' * 16
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)


def main():
    try:
        payload = open(sys.argv[1], "rb").read()
    except:
        print("File argument needed! %s <raw payload file>" % sys.argv[0])
        sys.exit()

    # encrypt payload and print the random AES key
    ct = encrypt_AES(payload, KEY)
    print('char AESkey[] = { 0x' + ', 0x'.join(hex(ord(chr(x)))[2:] for x in KEY) + ' };')
    print('char Payload[] = { 0x' + ', 0x'.join(hex(ord(chr(x)))[2:] for x in ct) + ' };')


if __name__ == '__main__':
    main()