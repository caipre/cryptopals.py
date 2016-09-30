import os
import random

from Crypto.Cipher import AES

def randcrypt(plaintext):
    def pad(text, size):
        padlen = size - (len(text) % size)
        return text + chr(padlen) * padlen

    iv = os.urandom(AES.block_size)
    key = os.urandom(AES.block_size)
    xxx = os.urandom(random.randint(5, 10))
    mplaintext = pad(xxx + plaintext + xxx, AES.block_size)


    if random.random() < 0.5:
        ecb = AES.new(key=key, mode=AES.MODE_ECB)
        return ecb.encrypt(mplaintext), 'ECB'
    else:
        cbc = AES.new(IV=iv, key=key, mode=AES.MODE_CBC)
        return cbc.encrypt(mplaintext), 'CBC'

def attacktext():
    plaintext = ''
    for i in range(AES.block_size + 1):
        plaintext += 'x' * (AES.block_size * 2)
        plaintext += ' ' * (AES.block_size - i)
    return plaintext

def detect(ciphertext):
    for i in range(len(ciphertext)-AES.block_size):
        j = i + AES.block_size
        k = j + AES.block_size
        if ciphertext[i] == ciphertext[j] and ciphertext[i:j] == ciphertext[j:k]:
            return 'ECB'
    return 'CBC'


for i in range(10000):
    plaintext = attacktext()
    ciphertext, mode = randcrypt(plaintext)
    detected = detect(ciphertext)
    assert detected == mode
