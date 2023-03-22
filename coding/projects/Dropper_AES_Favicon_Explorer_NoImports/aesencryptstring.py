#!/usr/bin/env python3
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom
from random import choice
import hashlib
import string
import sys

key = urandom(16)

def encrypt_AES(plaintext, key):
    k = hashlib.sha256(key).digest()
    iv = b'\x00' * 16
    plaintext = pad(plaintext, AES.block_size)
    cipher = AES.new(k, AES.MODE_CBC, iv)
    return cipher.encrypt(plaintext)

def print_key():
    # print out the key for the function name string
    out = "unsigned char key[] = "
    out_hex = '{ 0x' + ', 0x'.join(hex(ord(chr(x)))[2:] for x in key) + ' };'
    
    print("\n[+] Printing the AES encryption key c variable:")
    print(out + out_hex)

def encr_string(string):
    # add null byte \x00 to string
    string_w_null = string.encode() + b'\x00'
    enc_name = encrypt_AES(string_w_null, key)

    # print out the function name string
    out = "AES encrypted string: "
    out_hex = '{ 0x' + ', 0x'.join(hex(ord(chr(x)))[2:] for x in enc_name) + ' };'
    out_n = "\n"
    
    print(out + out_hex + out_n)

def main():
    print_key()
    print("")
    
    keep_going = True
    while keep_going:
        plaintext = input("[+] String to AES-encrypt: ")
        
        if plaintext == "quit":
            break
            
        encr_string(plaintext)
        
if __name__ == "__main__":
    main()