import os
import random

from Crypto.Cipher import AES

KEY = os.urandom(AES.block_size)
def randcrypt(plaintext):
    global KEY
    salt = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg' \
           'aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq' \
           'dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg' \
           'YnkK'.decode('base64')

    def pad(text, size):
        padlen = size - (len(text) % size)
        return text + chr(padlen) * padlen

    key = KEY
    #mplaintext = pad(plaintext + 'THIS IS A TEST STRING THAT IS LONG', AES.block_size)
    mplaintext = pad(plaintext + salt, AES.block_size)

    ecb = AES.new(key=key, mode=AES.MODE_ECB)
    return ecb.encrypt(mplaintext)

def detect_blocksize():
    def plaintexts():
        i = 1
        while True:
            yield 'x' * i
            i += 1

    cipherlen = None
    for plaintext in plaintexts():
        ciphertext = randcrypt(plaintext)
        if not cipherlen:
            cipherlen = len(ciphertext)
        elif cipherlen != len(ciphertext):
            return len(ciphertext) - cipherlen

def is_ecb(blocksize):
    def attacktext():
        plaintext = ''
        for i in range(blocksize + 1):
            plaintext += 'x' * (blocksize * 2)
            plaintext += ' ' * (blocksize - i)
        return plaintext

    plaintext = attacktext()
    ciphertext = randcrypt(plaintext)
    for i in range(len(ciphertext)-blocksize):
        j = i + blocksize
        k = j + blocksize
        if ciphertext[i] == ciphertext[j] and ciphertext[i:j] == ciphertext[j:k]:
            return True
    return False

def decrypt(blocksize):
    plaintext = ''
    solvingblock = 1
    while True:
        crafty = 'x' * (blocksize * solvingblock - len(plaintext) - 1)
        craftycipher = randcrypt(crafty)
        learned = False
        for byte in range(256):
            attacktext = crafty + plaintext + chr(byte)
            ciphertext = randcrypt(attacktext)
            if ciphertext[:blocksize*solvingblock] == craftycipher[:blocksize*solvingblock]:
                solvingblock = ((len(plaintext) + 1) / blocksize) + 1
                plaintext += chr(byte)
                learned = True
                break
        if not learned:
            break
    return plaintext



blocksize = detect_blocksize()
assert blocksize == AES.block_size
assert is_ecb(blocksize)
print 'blocksize:', blocksize
print decrypt(blocksize)
