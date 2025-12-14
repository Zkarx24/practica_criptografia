from Crypto.Cipher import AES

key = bytes.fromhex("A2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72")
zero = bytes(16)  # bloque de 16 bytes en cero
iv = bytes(16)    # IV en cero

cipher = AES.new(key, AES.MODE_CBC, iv)
out = cipher.encrypt(zero)
print("KCV AES:", out.hex()[:6])
