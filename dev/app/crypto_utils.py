import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging

class CryptoManager:
    def __init__(self, logger=None):
        self.logger = logger or logging.getLogger("CertAutomator.Crypto")
        self.magic_header = b'ENC:'

    def _derive_key(self, password: str, salt: bytes) -> bytes:
        """Derives a Fernet-compatible key from a password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_data(self, data: dict, password: str) -> bytes:
        """
        Encrypts a dictionary into a byte string.
        Format: ENC:[16_byte_salt][encrypted_payload]
        """
        salt = os.urandom(16)
        key = self._derive_key(password, salt)
        fernet = Fernet(key)
        
        json_str = json.dumps(data)
        encrypted_payload = fernet.encrypt(json_str.encode())
        
        return self.magic_header + salt + encrypted_payload

    def decrypt_data(self, file_content: bytes, password: str) -> dict:
        """
        Decrypts bytes back into a dictionary.
        Expects content to start with ENC:.
        """
        if not file_content.startswith(self.magic_header):
            raise ValueError("Invalid file format (missing magic header)")
            
        # Extract salt (16 bytes after header)
        header_len = len(self.magic_header)
        salt = file_content[header_len : header_len + 16]
        encrypted_payload = file_content[header_len + 16 :]
        
        key = self._derive_key(password, salt)
        fernet = Fernet(key)
        
        decrypted_bytes = fernet.decrypt(encrypted_payload)
        return json.loads(decrypted_bytes.decode())

    def is_encrypted(self, file_path: str) -> bool:
        """Checks if a file is likely encrypted by reading the magic header."""
        if not os.path.exists(file_path):
            return False
        try:
            with open(file_path, 'rb') as f:
                header = f.read(len(self.magic_header))
                return header == self.magic_header
        except Exception:
            return False
