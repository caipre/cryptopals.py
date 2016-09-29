def score(plaintext):
    sum = 0
    for char in plaintext:
        if char in 'eato ':
            sum += 10
        elif char in 'inshr':
            sum += 6
        elif char in 'dlcum':
            sum += 3
        elif char in 'wfgyp':
            sum += 2
        elif char in 'bvk':
            sum += 1
    return sum

def decode(key, ciphertext):
    return ''.join(map(lambda x: chr(key ^ ord(x)), ciphertext.decode('hex')))

def key_for(ciphertext):
    scores = {char: 0 for char in range(256)}
    for i in range(256):
        plaintext = decode(i, ciphertext)
        scores[i] = score(plaintext)

    key = max(scores.keys(), key=lambda k: scores[k])
    return key


ciphertext = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'
key = key_for(ciphertext)
print 'key:', chr(key)
print decode(key, ciphertext)
