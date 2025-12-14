from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Master Key (hex)
master_hex = "A2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72"

# Identificador del dispositivo (salt en hex)
salt_hex = "e43bb4067bcbfab3bec54437b84bef4623e345682d89de9948fbb0afedc461a3"

master_key = bytes.fromhex(master_hex)
salt = bytes.fromhex(salt_hex)

hkdf = HKDF(
    algorithm=hashes.SHA512(),
    length=32,          # 256 bits
    salt=salt,
    info=b""
)

derived_key = hkdf.derive(master_key)

print("Clave derivada (hex):")
print(derived_key.hex())
