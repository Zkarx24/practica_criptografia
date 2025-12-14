from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import ed25519

mensaje = b"El equipo esta preparado para seguir con el proceso, necesitaremos mas recursos."

raw = Path("ed25519-priv").read_bytes()
seed = raw[:32]  # usamos solo el seed

priv_key = ed25519.Ed25519PrivateKey.from_private_bytes(seed)

firma = priv_key.sign(mensaje)

print("Firma Ed25519 (hex):")
print(firma.hex())
