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
    return ''.join(map(lambda x: chr(key ^ ord(x)), ciphertext))

def key_for(ciphertext):
    scores = {char: 0 for char in range(256)}
    for i in range(256):
        plaintext = decode(i, ciphertext)
        scores[i] = score(plaintext)

    return max(scores.keys(), key=lambda k: scores[k])

def hamming(left, right):
    return sum(bin(ord(l) ^ ord(r)).count('1') for l, r in zip(left, right))

def chunks(size, text):
    i = 0
    while True:
        yield text[i:i+size]
        i += size
        if len(text[i:]) <= size:
            yield text[i:]
            break

def guess_keysize(ciphertext):
    scores = {keysize: 0 for keysize in range(2, 40)}
    for keysize in range(2, 40):
        firstblock = ciphertext[:keysize]
        scores[keysize] = sum(hamming(firstblock, other) for other in chunks(keysize, ciphertext))
        scores[keysize] /= float(len(ciphertext))

    return min(scores.keys(), key=lambda x: scores[x])

def transpose(chunks):
    return map(None, *map(lambda s: list(s), chunks))

def break_repxor(file):
    with open(file, 'r') as f:
        ciphertext = f.read().replace('\n', '').decode('base64')
    keysize = guess_keysize(ciphertext)

    blocks = list(chunks(keysize, ciphertext))
    blocks = transpose(blocks)

    key = ''
    for block in blocks:
        key += chr(key_for(''.join([c for c in block if c is not None])))

    return key, ciphertext

def xor(left, right):
    return chr(ord(left) ^ ord(right))

def decrypt(key, ciphertext):
    i = 0
    plaintext = ''
    for b in ciphertext:
        plaintext += xor(b, key[i])
        i = (i + 1) % len(key)

    return plaintext


assert hamming('this is a test', 'wokka wokka!!!') == 37
key, ciphertext = break_repxor('../etc/repeating-key-xor.in')
print 'key:', key
print decrypt(key, ciphertext)
