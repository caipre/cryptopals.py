from Crypto.Cipher import AES

def xor(left, right):
    return ''.join([chr(ord(l) ^ ord(r)) for l, r in zip(list(left), list(right))])

def pad(plaintext, blocksize):
    padlen = blocksize - (len(plaintext) % blocksize)
    return plaintext + chr(padlen) * padlen

def unpad(text):
    padlen = ord(text[-1])
    return text[:-padlen]

def chunks(size, text):
    i = 0
    while True:
        yield text[i:i+size]
        i += size
        if len(text[i:]) <= size:
            yield text[i:]
            break

def encrypt_aes_ecb_cbc(iv, key, plaintext):
    ecb = AES.new(key=key, mode=AES.MODE_ECB)
    ciphertext = ''
    plaintext = pad(plaintext, AES.block_size)
    prev = iv
    for block in chunks(len(key), plaintext):
        xblock = xor(prev, block)
        eblock = ecb.encrypt(xblock)
        prev = eblock
        ciphertext += eblock
    return ciphertext

def decrypt_aes_ebc_cbc(iv, key, ciphertext):
    ecb = AES.new(key=key, mode=AES.MODE_ECB)
    plaintext = ''
    prev = iv
    for block in chunks(len(key), ciphertext):
        xblock = ecb.decrypt(block)
        pblock = xor(prev, xblock)
        prev = block
        plaintext += pblock
    return unpad(plaintext)

def pycrypto_aes_cbc(iv, key, plaintext):
    cbc = AES.new(IV=iv, key=key, mode=AES.MODE_CBC)
    return cbc.encrypt(pad(plaintext, AES.block_size))

def cryptopals(file, iv, key):
    with open(file, 'r') as f:
        ciphertext = f.read().replace('\n', '').decode('base64')
    return decrypt_aes_ebc_cbc(iv, key, ciphertext)

iv = chr(0x0) * AES.block_size
key = 'YELLOW SUBMARINE'
plaintext = 'this is a test string to be encrypted'
ciphertext = encrypt_aes_ecb_cbc(iv, key, plaintext)
assert ciphertext == pycrypto_aes_cbc(iv, key, plaintext)
assert plaintext == decrypt_aes_ebc_cbc(iv, key, ciphertext)

print cryptopals('../etc/aes-cbc.in', iv, key)
