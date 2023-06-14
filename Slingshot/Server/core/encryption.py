
def RC4Crypt(data, key):
    """Perform RC4 En/Decryption against data with specified key""" 
    x = 0
    box = list(range(256))
    for i in range(256):
        x = (x + int(box[i]) + int(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]

    x = y = 0
    out = []

    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(char ^ box[(box[x] + box[y]) % 256])
        
    return b''.join([bytes([o]) for o in out])