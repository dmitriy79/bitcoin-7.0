import ecdsa
import hashlib

def sign_with_private_key(private_key_hex, sighash_hex, raw_tx_hex):
    # Порядок кривой
    N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
    HALF_N = N // 2

    # Создаем объект приватного ключа
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(private_key_hex), curve=ecdsa.SECP256k1)
    
    # Подписываем РЕАЛЬНЫЙ хэш транзакции, который требует 15-я нода
    signature = sk.sign_digest(bytes.fromhex(sighash_hex), sigencode=ecdsa.util.sigencode_der)
    
    # Извлекаем R и S из DER структуры для проверки на Low-S
    # (Python ecdsa по умолчанию делает каноничные подписи, но мы перестрахуемся)
    r, s = ecdsa.util.sigdecode_der(signature, sk.curve.generator.order())
    if s > HALF_N:
        s = N - s
        signature = ecdsa.util.sigencode_der(r, s, sk.curve.generator.order())
        
    # Добавляем тип хэширования SIGHASH_ALL (0x01)
    signature += b'\x01'
    
    # Сжатый публичный ключ вашей ноды
    pubkey = bytes.fromhex("02d7e9ba80c1b2c6ba9189a1733615791b022c9d5b1d902ab76074897292dec76e")
    
    # Собираем новый чистый ScriptSig (размер подписи + подпись + размер ключа + ключ)
    script_sig = bytes([len(signature)]) + signature + bytes([len(pubkey)]) + pubkey
    
    # Внедряем ScriptSig обратно в оригинальный скелет транзакции
    raw_tx = bytes.fromhex(raw_tx_hex)
    header = raw_tx[:41] # До ScriptSig
    footer = raw_tx[148:] # После ScriptSig (Sequence + Выходы)
    
    final_tx = header + bytes([len(script_sig)]) + script_sig + footer
    print("[!] ПОЛНОСТЬЮ ВАЛИДНЫЙ HEX ДЛЯ ОТПРАВКИ:")
    print(final_tx.hex())

# Сюда мы вставим данные:
# priv_key = "ВАШ_ПРИВАТНЫЙ_КЛЮЧ_В_HEX"
# real_sighash = "ХЭШ_ИЗ_ЛОГА_15_НОДЫ"
# sign_with_private_key(priv_key, real_sighash, "0100000001fc51ce...")
