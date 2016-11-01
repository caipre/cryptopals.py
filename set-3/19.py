import os
from Crypto.Cipher import AES

def blocks(text):
    i = 0
    while i + AES.block_size < len(text):
        yield text[i:i+AES.block_size]
        i += AES.block_size
    yield text[i:]

def numbytes(num, width=8):
    l = [chr(0) for i in range(width)]
    l[0] = chr(num % 256)
    i = 1
    while num >= 256:
        l[i] = chr(num / (256 ** i))
        num -= 256 ** i
        i += 1
    return ''.join(l)

def xor(stra, strb):
    return ''.join(map(lambda (a, b): chr(ord(a) ^ ord(b)), zip(list(stra), list(strb))))

def ctrcrypt(key, nonce, text):
    ret = ''
    counter = 0
    ecb = AES.new(key=key, mode=AES.MODE_ECB)
    for block in blocks(text):
        ctrcipher = ecb.encrypt(numbytes(nonce) + numbytes(counter))
        ret += xor(block, ctrcipher)
        counter += 1
    return ret

def encryptions(file):
    key = os.urandom(AES.block_size)
    nonce = 0
    with open(file, 'r') as f:
        for line in f:
            line = line.strip().decode('base64')
            yield ctrcrypt(key, nonce, line)

def transpose(strs):
    return map(None, *map(lambda s: list(s), strs))

def key_for(bytes):
    def freq(char):
        char = chr(char).lower()
        if char in 'eato ':
            return 15
        elif char in 'inshr':
            return 8
        elif char in 'dlcum':
            return 5
        elif char in '!.",-;:':
            return 2
        elif char in 'wfgyp':
            return 2
        elif char in 'bvk':
            return 1
        return -10

    scores = {char: 0 for char in range(256)}
    for byte in range(256):
        for cipherbyte in bytes:
            if not cipherbyte:
                continue
            scores[byte] += freq(ord(cipherbyte) ^ byte)
    return max(scores.keys(), key=lambda k: scores[k])

def cryptopals():
    ciphertexts = list(encryptions('../etc/fixed-nonce-ctr.in'))
    maxlen = len(max(ciphertexts, key=len))
    bytes = transpose(ciphertexts)
    keystream = ''
    for i in range(maxlen):
        keystream += chr(key_for(bytes[i]))
    for ciphertext in ciphertexts:
        print xor(ciphertext, keystream)


cryptopals()
