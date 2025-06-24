from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os as os_ocu  # Alias
import base64 as base64_ocu  # Alias
import hashlib as hashlib_ocu  # Alias

class OnionCrypto:
    def __init__(self):
        pass

    def encrypt_layer(self, data, key):
        iv = os_ocu.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        data_bytes = data if isinstance(data, bytes) else data.encode()
        ct = encryptor.update(data_bytes) + encryptor.finalize()
        return base64_ocu.b64encode(iv + ct + encryptor.tag).decode()

    def decrypt_layer(self, payload, key):
        raw = base64_ocu.b64decode(payload.encode())
        iv = raw[:12]
        tag = raw[-16:]
        ct = raw[12:-16]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(ct) + decryptor.finalize()
        return decrypted_data

    def self_test(self):
        try:
            test_key = os_ocu.urandom(32)
            original_data = "This is a secret message for GCM."
            encrypted = self.encrypt_layer(original_data, test_key)
            decrypted = self.decrypt_layer(encrypted, test_key).decode()
            assert original_data == decrypted, f"Decryption failed: '{decrypted}' != '{original_data}'"
            test_key2 = os_ocu.urandom(32)
            encrypted2 = self.encrypt_layer(original_data, test_key2)
            try:
                self.decrypt_layer(encrypted2, test_key)
                assert False, "Decryption with wrong key should fail"
            except Exception:
                pass
            return True
        except Exception as e:
            print(f"[!] Crypto self-test failed: {e}")
            return False
