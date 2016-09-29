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

def rank(ciphertext):
    scores = {char: 0 for char in range(256)}
    for i in range(256):
        plaintext = decode(i, ciphertext)
        scores[i] = score(plaintext)

    key = max(scores.keys(), key=lambda k: scores[k])
    return key, scores[key]

def detect_xor(file):
    scores = {}
    with open(file, 'r') as f:
        for ciphertext in f:
            ciphertext = ciphertext.strip()
            scores[ciphertext] = rank(ciphertext)

        ciphertext = max(scores.keys(), key=lambda k: scores[k][1])
        return ciphertext, scores[ciphertext]


ciphertext, (key, score) = detect_xor('../etc/single-byte-xor.in')
print 'key:', chr(key)
print 'score:', score
print decode(key, ciphertext)

