from pathlib import Path
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

# ==========
# CONFIG
# ==========
CIPHERTEXT_HEX = (
    "b72e6fd48155f565dd2684df3ffa8746d649b11f0ed4637fc4c99d18283b32e1709b30c"
    "96b4a8a20d5dbc639e9d83a53681e6d96f76a0e4c279f0dffa76a329d04e3d3d4ad629"
    "793eb00cc76d10fc00475eb76bfbc1273303882609957c4c0ae2c4f5ba670a4126f2f14"
    "a9f4b6f41aa2edba01b4bd586624659fca82f5b4970186502de8624071be78ccef573d"
    "896b8eac86f5d43ca7b10b59be4acf8f8e0498a455da04f67d3f98b4cd907f27639f4b1"
    "df3c50e05d5bf63768088226e2a9177485c54f72407fdf358fe64479677d8296ad38c6f"
    "177ea7cb74927651cf24b01dee27895d4f05fb5c161957845cd1b5848ed64ed3b0372"
    "2b21a526a6e447cb8ee"
)

PRIV_PEM_PATH = "clave-rsa-oaep-priv.pem"
PUBL_PEM_PATH = "clave-rsa-oaep-publ.pem"

# ==========
# HELPERS
# ==========
def load_private_key(path: str):
    data = Path(path).read_bytes()
    return serialization.load_pem_private_key(data, password=None)

def load_public_key(path: str):
    data = Path(path).read_bytes()
    return serialization.load_pem_public_key(data)

def clean_hex(s: str) -> str:
    # elimina espacios/saltos de línea por si se copia con saltos de mas
    return "".join(s.split())

# ==========
# MAIN
# ==========
def main():
    # 1) Cargar claves
    priv = load_private_key(PRIV_PEM_PATH)
    pub = load_public_key(PUBL_PEM_PATH)

    # 2) Preparar ciphertext
    hex_str = clean_hex(CIPHERTEXT_HEX)
    if len(hex_str) % 2 != 0:
        raise ValueError(f"Hex inválido: largo impar ({len(hex_str)}). Falta/sobra un caracter.")

    ciphertext = bytes.fromhex(hex_str)

    # 3) Validación de tamaño RSA
    key_bytes = priv.key_size // 8
    print(f"[i] Tamano clave RSA: {priv.key_size} bits ({key_bytes} bytes)")
    print(f"[i] Tamano ciphertext: {len(ciphertext)} bytes")

    if len(ciphertext) != key_bytes:
        raise ValueError(
            "El ciphertext NO coincide con el tamaño del bloque RSA.\n"
            f"Se esperaban {key_bytes} bytes, pero llegaron {len(ciphertext)}.\n"
            "Esto casi siempre significa que el hex fue copiado con caracteres extra o faltantes."
        )

    # 4) Descifrar RSA-OAEP con SHA-256 (hash y MGF1 = SHA-256)
    plaintext = priv.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("\n=== CLAVE SIMETRICA RECUPERADA ===")
    print("[hex]", plaintext.hex())
    print("[len]", len(plaintext), "bytes")

    # 5) Volver a cifrar con la pública (mismo OAEP+SHA-256)
    ciphertext2 = pub.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    print("\n=== RE-CIFRADO RSA-OAEP ===")
    print("[hex]", ciphertext2.hex())
    print("[len]", len(ciphertext2), "bytes")

    # 6) Comparación
    same = ciphertext2 == ciphertext
    print("\n=== COMPARACION ===")
    print("Textos cifrados son iguales?:", same)


if __name__ == "__main__":
    main()
