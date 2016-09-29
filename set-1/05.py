def xor(left, right):
    return chr(ord(left) ^ ord(right))

def encrypt(key, plaintext):
    i = 0
    ciphertext = ''
    for b in plaintext:
        ciphertext += xor(b, key[i])
        i = (i + 1) % len(key)

    return ciphertext.encode('hex')

key = 'ICE'
plaintext = "Burning 'em, if you ain't quick and nimble\n" \
            "I go crazy when I hear a cymbal"

ret = encrypt(key, plaintext)
print ret
assert ret == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272" \
              "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
