import hashlib

key = bytes.fromhex("A2CFF885901A5449E9C448BA5B948A8C4EE377152B3F1ACFA0148FB3A426DB72")
digest = hashlib.sha256(key).hexdigest()
print("KCV SHA256:", digest[:6])
