import os
import random

from Crypto.Cipher import AES

KEY = os.urandom(AES.block_size)
#PRE = os.urandom(random.randint(1, 64))
PRE = os.urandom(random.randint(14, 14))
def randcrypt(plaintext):
    global KEY
    global PRE

    salt = 'aG93IGRvIHlvdSBsaWtlIHRoZW0gYXBwbGVz'.decode('base64')

    def pad(text, size):
        padlen = size - (len(text) % size)
        return text + chr(padlen) * padlen

    pre = PRE
    key = KEY
    mplaintext = pad(pre + plaintext + salt, AES.block_size)

    ecb = AES.new(key=key, mode=AES.MODE_ECB)
    return ecb.encrypt(mplaintext)

def detect_prefix():
    def plaintexts():
        i = 1
        while True:
            yield 'x' * i
            i += 1

    stimulus = randcrypt('stimulus')
    response = randcrypt('response')

    skipblocks = 0
    for i, (a, b) in enumerate(zip(list(stimulus), list(response))):
        if a != b:
            skipblocks = i / AES.block_size
            break

    skipbytes = skipblocks * AES.block_size

    prevcipher = ""
    for plaintext in plaintexts():
        ciphertext = randcrypt(plaintext)
        #print "----------------------------------"
        #print 'plain', plaintext
        #print 'prev ', blocks(prevcipher)
        #print 'ciphr', blocks(ciphertext)
        #print
        #print 'prskp', blocks(prevcipher[:skipbytes+AES.block_size])
        #print 'ciskp', blocks(ciphertext[:skipbytes+AES.block_size])
        #print
        #print 'prlen', blocks(prevcipher[:skipbytes+len(plaintext)-1])
        #print 'cilen', blocks(ciphertext[:skipbytes+len(plaintext)-1])
        #print "----------------------------------"
        #assert len(plaintext) < 18
        if prevcipher[:skipbytes+AES.block_size] == ciphertext[:skipbytes+AES.block_size]:
            return skipbytes+AES.block_size-len(plaintext)+1, len(plaintext)-1
        else:
            prevcipher = ciphertext

def blocks(ciphertext):
    blocks = []
    str = ciphertext.encode('hex')
    step = AES.block_size * 2
    for i in range(0, min(len(str), 173), step):
        blocks.append(str[i:i+step])
    return ' '.join(blocks)


def decrypt(prefixlen, filllen):
    plaintext = ''
    skipblocks = (prefixlen + filllen) / AES.block_size
    solvingblock = 1
    while True:
        #crafty = 'x' * (prefixlen + (AES.block_size * solvingblock - len(plaintext) - 1))
        crafty = ('x' * filllen) + ('x' * ((AES.block_size * solvingblock) - len(plaintext) - 1))
        craftycipher = randcrypt(crafty)
        #print 'crafty ', solvingblock, blocks(craftycipher)
        learned = False
        for byte in range(256):
            attacktext = crafty + plaintext + chr(byte)
            ciphertext = randcrypt(attacktext)
            #print 'cipher ', solvingblock, blocks(ciphertext)
            #print '           ' + ' ' * (2*AES.block_size*skipblocks) + '^'
            #print '             ' + ' ' * (2*AES.block_size*(skipblocks+solvingblock)) + '^'
            if ciphertext[:AES.block_size*(skipblocks+solvingblock)] == craftycipher[:AES.block_size*(skipblocks+solvingblock)]:
                solvingblock = (len(plaintext) + 1) / AES.block_size + 1
                plaintext += chr(byte)
                learned = True
                break
        if not learned:
            break
    return plaintext


prefixlen, filllen = detect_prefix()
print decrypt(prefixlen, filllen)
