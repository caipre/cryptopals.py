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

key = 'YELLOW SUBMARINE'
nonce = 0
plaintext = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='.decode('base64')
print ctrcrypt(key, nonce, plaintext)
