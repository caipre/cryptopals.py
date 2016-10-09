import os
import random

from Crypto.Cipher import AES

KEY = os.urandom(AES.block_size)
#KEY = 'new phish album.'

def blocks(ciphertext):
    blocks = []
    str = ciphertext.encode('hex')
    step = AES.block_size * 2
    for i in range(0, min(len(str), 120), step):
        blocks.append(str[i:i+step])
    return ' '.join(blocks)

def pad(text, size=AES.block_size):
    padlen = size - (len(text) % size)
    return text + chr(padlen) * padlen

def unpad(text):
    padlen = ord(text[-1])
    return text[:-padlen]

def encrypt():
    global KEY

    strings = [
        'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
        'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
        'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
        'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
        'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
        'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
        'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
        'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
        'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
        'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
    ]

    string = random.choice(strings)
    padstr = pad(string.decode('base64'))
    #padstr = pad('yellow submarine')

    iv = chr(0x0) * AES.block_size
    key = KEY

    cbc = AES.new(IV=iv, key=key, mode=AES.MODE_CBC)
    return cbc.encrypt(padstr), iv

def check(ciphertext):
    global KEY

    def check_(text):
        padnum = ord(text[-1])
        if not 1 <= padnum <= 16:
            return False
        if not text[-padnum:] == chr(padnum) * padnum:
            return False
        return True

    iv = chr(0x0) * AES.block_size
    key = KEY

    cbc = AES.new(IV=iv, key=key, mode=AES.MODE_CBC)
    paddedtext = cbc.decrypt(ciphertext)
    return check_(paddedtext)

def blocks(ciphertext):
    blocks = []
    str = ciphertext.encode('hex')
    step = AES.block_size * 2
    for i in range(0, len(str), step):
        blocks.append(str[i:i+step])
    return ' '.join(blocks)

def padattack():
    def blockpairs(text):
        i = 0
        while i + AES.block_size < len(text):
            yield text[i:i+AES.block_size], text[i+AES.block_size:i+2*AES.block_size]
            i += AES.block_size

    def solvebyte(pos, blocka, blockb, known):
        for char in range(256):
            block = list(blocka)
            block[-pos] = chr(ord(block[-pos]) ^ char ^ pos)
            for i in range(pos-1,0,-1):
                block[-i] = chr(ord(block[-i]) ^ ord(known[-i]) ^ pos)
            trycipher = ''.join(block) + blockb
            if check(trycipher):
                return chr(char)

    ciphertext, iv = encrypt()
    print blocks(iv + ciphertext)
    for blocka, blockb in blockpairs(iv + ciphertext):
        print blocka.encode('hex'), blockb.encode('hex')
        known = [None for i in range(AES.block_size)]
        for i in range(1,17):
            c = solvebyte(i, blocka, blockb, known)
            if c: known[-i] = c
        print ''.join(known)

padattack()
