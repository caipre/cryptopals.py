def pad(text, size=16):
    padlen = size - (len(text) % size)
    return text + chr(padlen) * padlen

def unpad(text):
    padnum = ord(text[-1])
    if not 1 <= padnum <= 16:
        return False
    if not text[-padnum:] == chr(padnum) * padnum:
        return False
    return True

assert unpad(pad('ICE ICE BABY'))
assert unpad('ICE ICE BABY' + chr(0x04) * 4)

assert not unpad('ICE ICE BABY' + chr(0x05) * 4)
assert not unpad('ICE ICE BABI' + chr(0x01) + chr(0x02) + chr(0x03) + chr(0x04))
