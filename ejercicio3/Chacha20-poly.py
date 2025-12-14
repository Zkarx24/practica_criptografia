from Crypto.Cipher import ChaCha20
from Crypto.Hash import HMAC, SHA256
import base64

# Clave del keystore (hex)
KEY_HEX = "af9df30474898787a45605ccb9b936d33b780d03cabc81719d52383480dc3120"
clave = bytes.fromhex(KEY_HEX)

# Nonce entregado en el enunciado (base64)
nonce = base64.b64decode("9Yccn/f5nJJhAt2S")

# Mensaje
mensaje = "KeepCoding te enseña a codificar y a cifrar".encode("utf-8")

# Cifrado ChaCha20
cipher = ChaCha20.new(key=clave, nonce=nonce)
texto_cifrado = cipher.encrypt(mensaje)

# HMAC para añadir integridad
hmac = HMAC.new(clave, digestmod=SHA256)
hmac.update(nonce + texto_cifrado)
tag = hmac.digest()

# Convertir todo a Base64 para enviar
nonce_b64 = base64.b64encode(nonce).decode()
cipher_b64 = base64.b64encode(texto_cifrado).decode()
tag_b64 = base64.b64encode(tag).decode()

print("Nonce:", nonce_b64)
print("Texto cifrado:", cipher_b64)
print("Tag:", tag_b64)
