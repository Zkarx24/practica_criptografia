from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from pathlib import Path

mensaje = b"El equipo esta preparado para seguir con el proceso, necesitaremos mas recursos."

priv_key = serialization.load_pem_private_key(
    Path("clave-rsa-oaep-priv.pem").read_bytes(),
    password=None
)

firma_rsa = priv_key.sign(
    mensaje,
    padding.PKCS1v15(),
    hashes.SHA256()
)

print("Firma RSA (hex):")
print(firma_rsa.hex())
