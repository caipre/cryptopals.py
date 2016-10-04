import os
from Crypto.Cipher import AES

def decode(str):
    return {k: v for k, v in map(lambda kvp: kvp.split('='), str.split('&'))}

def urlencode(dict):
    # dict keys unordered, we need `&role=` at the end
    #return '&'.join(map(lambda (k, v): "{0}={1}".format(k, v), dict.items()))
    return "email={0}&uid={1}&role={2}".format(dict['email'], dict['uid'], dict['role'])

users = {}
def profile_for(email):
    global users
    if email not in users:
        users[email] = { 'email': email.replace('&', '').replace('=', ''),
                         'uid': len(users.keys()), 'role': 'user' }
    return urlencode(users[email])

def pad(text):
    padlen = AES.block_size - (len(text) % AES.block_size)
    return text + chr(padlen) * padlen

def encrypt(email):
    global key

    userdata = profile_for(email)
    ecb = AES.new(key=key, mode=AES.MODE_ECB)
    return ecb.encrypt(pad(userdata))

def decrypt(ciphertext):
    global key
    def unpad(text):
        padlen = ord(text[-1])
        return text[:-padlen]

    ecb = AES.new(key=key, mode=AES.MODE_ECB)
    return unpad(ecb.decrypt(ciphertext))

def get_admin():
    # TODO: programmatically determine the necessary shifting
    plaincipher = encrypt('ok@example.org')
    admincipher = encrypt('craftytext' + pad('admin'))
    return plaincipher[:-AES.block_size] + admincipher[AES.block_size:AES.block_size*2]

key = os.urandom(AES.block_size)
attackcipher = get_admin()
assert decode(decrypt(attackcipher))['role'] == 'admin'
