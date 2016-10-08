import os

from Crypto.Cipher import AES

KEY = os.urandom(AES.block_size)

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

def encrypt(plaintext):
    global KEY

    prefix = 'comment1=cooking%20MCs;userdata='
    suffix = ';comment2=%20like%20a%20pound%20of%20bacon'

    iv = chr(0x0) * AES.block_size
    key = KEY

    mplaintext = plaintext.replace(';', '%3b').replace('=', '%3d') # such secure, much safety
    mplaintext = pad(prefix + plaintext + suffix)

    cbc = AES.new(IV=iv, key=key, mode=AES.MODE_CBC)
    return cbc.encrypt(mplaintext)

def is_admin(ciphertext):
    global KEY

    iv = chr(0x0) * AES.block_size
    key = KEY

    cbc = AES.new(IV=iv, key=key, mode=AES.MODE_CBC)
    plaintext = unpad(cbc.decrypt(ciphertext))

    for k, v in map(lambda kvp: kvp.split('='), plaintext.split(';')):
        if k == 'admin':
            return True
    return False

def bitflip():
    def flip(char, bit):
        return chr(ord(char) ^ 0x1 << bit)
    attacktext = '::garbageblock::' + '?admin?true'
    admincipher = encrypt(attacktext)
    arrcipher = list(admincipher)
    for offset, bit in map(lambda (o, b): (o + AES.block_size * 2, b), [(0, 2), (6, 1)]):
        arrcipher[offset] = flip(arrcipher[offset], bit)
    attackcipher = ''.join(arrcipher)

    return attackcipher


attackcipher = bitflip()
assert is_admin(attackcipher)
