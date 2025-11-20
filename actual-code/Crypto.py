from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

class CryptoHandler:
    def __init__(self):
        self.key = None
        self.cipher = None

    def set_secret_key(self, key: bytes):
        if len(key) not in [16, 24, 32]:  # Valid AES key sizes
            raise ValueError("Key must be 16, 24, or 32 bytes long")
        self.key = key
        print("Secret key set.")

    def encrypt(self, data: bytes) -> bytes:
        if not self.key:
            raise ValueError("Secret key not set")
        iv = get_random_bytes(16)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        ciphertext = cipher.encrypt(pad(data, AES.block_size))
        return iv + ciphertext  # Prepend IV for later decryption

    def decrypt(self, encrypted_data: bytes) -> bytes:
        if not self.key:
            raise ValueError("Secret key not set")
        iv = encrypted_data[:16]
        ciphertext = encrypted_data[16:]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext


# Example usage
crypto = CryptoHandler()
crypto.set_secret_key(b'ThisIsA16ByteKey')

message = b"Hello, world!"
encrypted = crypto.encrypt(message)
print("Encrypted:", encrypted)

decrypted = crypto.decrypt(encrypted)
print("Decrypted:", decrypted)
