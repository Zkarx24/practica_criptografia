from base64 import b64decode
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# Clave EXACTA en MAYÚSCULAS desde tu keystore
key_hex = "A2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72"
key = bytes.fromhex(key_hex)

# IV de 16 bytes en cero
iv = bytes.fromhex("00" * 16)

cipher_b64 = "TQ9SOMKc6aFS9SlxhfK9wT18UXpPCd505Xf5J/5nLI7Of/o0QKIWXg3nu1RRz4QWElezdrLAD5LO4USt3aB/i50nvvJbBiG+le1ZhpR84oI="
cipher_bytes = b64decode(cipher_b64)

cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext_padded = cipher.decrypt(cipher_bytes)

print("Bloque descifrado (con padding):", plaintext_padded)
print("Ultimo byte:", plaintext_padded[-1])

plaintext = unpad(plaintext_padded, 16, style="pkcs7")
print("Texto descifrado:", plaintext.decode("utf-8", errors="replace"))
