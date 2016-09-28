def repeats(ciphertext):
    repeats = 0
    for i in range(len(ciphertext)-16):
        block = ciphertext[i:i+16]
        j = i + 16
        while j < len(ciphertext):
            other = ciphertext[j:j+16]
            if block == other:
                repeats += 1
                j += 16
            else:
                j += 1

        if repeats:
            break
    return repeats

def detect_aes_ecb(file):
    with open(file, 'r') as f:
        lines = map(lambda l: l.strip(), f.readlines())
        ciphertexts = map(lambda l: l.decode('hex'), lines)

    scores = {}
    for ciphertext in ciphertexts:
        scores[ciphertext] = repeats(ciphertext)

    return max(scores.keys(), key=lambda k: scores[k]).encode('hex')

print detect_aes_ecb('../etc/detect-aes-ecb.in')
