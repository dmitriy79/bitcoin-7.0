import hashlib

def b58encode(v):
    digits = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    n = int.from_bytes(v, 'big')
    res = []
    while n > 0:
        n, r = divmod(n, 58)
        res.append(digits[r])
    res = ''.join(reversed(res))
    pad = 0
    for b in v:
        if b == 0: pad += 1
        else: break
    return '1' * pad + res

def b58encode_check(v):
    digest = hashlib.sha256(hashlib.sha256(v).digest()).digest()
    return b58encode(v + digest[:4])

def pubkey_to_p2sh_address(pubkey_hex, version_byte=b'\x05'):
    pubkey_bytes = bytes.fromhex(pubkey_hex)
    
    # 1. HASH160 от публичного ключа
    sha256_pub = hashlib.sha256(pubkey_bytes).digest()
    r = hashlib.new('ripemd160')
    r.update(sha256_pub)
    pubkey_hash = r.digest()
    
    # 2. Создание Redeem Script для SegWit (0x00 0x14 + хэш)
    redeem_script = b'\x00\x14' + pubkey_hash
    
    # 3. HASH160 от Redeem Script
    sha256_redeem = hashlib.sha256(redeem_script).digest()
    r2 = hashlib.new('ripemd160')
    r2.update(sha256_redeem)
    script_hash = r2.digest()
    
    # 4. Кодирование в Base58Check
    return b58encode_check(version_byte + script_hash)

if __name__ == "__main__":
    pubkey = "02195ecde8972de8c1633091f8a432a7eaac7f75989d71e316ad7ad51effbf85c6"
    version = b'\x05' 
    
    address = pubkey_to_p2sh_address(pubkey, version)
    print("Адрес на тройку: " + str(address))
