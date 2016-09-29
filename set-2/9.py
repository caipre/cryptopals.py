def pad(plaintext, blocksize):
    padlen = blocksize - (len(plaintext) % blocksize)
    return plaintext + chr(padlen) * padlen

def unpad(text):
    padlen = ord(text[-1])
    return text[:-padlen]

plaintext = 'YELLOW SUBMARINE'
assert pad(plaintext, 16) == plaintext + (chr(0x10) * 16)
assert pad(plaintext, 20) == plaintext + (chr(0x04) * 4)
assert unpad(pad(plaintext, 20)) == plaintext
