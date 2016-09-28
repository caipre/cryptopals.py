from Crypto.Cipher import AES

def decrypt_aes_ecb(key, file):
    with open(file, 'r') as f:
        ciphertext = f.read().replace('\n', '').decode('base64')

    aes = AES.new(key=key, mode=AES.MODE_ECB)
    return aes.decrypt(ciphertext)


key = 'YELLOW SUBMARINE'
ret = decrypt_aes_ecb(key, '../etc/aes-ecb.in')
print ret
