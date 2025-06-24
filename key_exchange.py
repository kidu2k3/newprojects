import os as os_ke  # Alias to avoid conflict with client's os import
import time as time_ke  # Alias
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

class KeyExchange:
    def __init__(self):
        self.private_key = ec.generate_private_key(ec.SECP384R1())
        self.public_key = self.private_key.public_key()

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

    def derive_shared_key(self, peer_pem):
        peer_public_key = serialization.load_pem_public_key(peer_pem.encode())
        ss = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"altnet-p2p-session-key-v1",
        ).derive(ss)
