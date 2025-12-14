import hmac, hashlib

key = bytes.fromhex("A212A51C997E14B4DF08D55967641B0677CA31E049E672A4B06861AA4D5826EB")

mensaje = "Siempre existe más de una forma de hacerlo, y más de una solución válida.".encode()

h = hmac.new(key, mensaje, hashlib.sha256).hexdigest()
print(h)
