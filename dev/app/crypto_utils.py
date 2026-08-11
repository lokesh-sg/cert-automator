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

    def generate_mvk(self) -> str:
        """Generates a random 256-bit Master Vault Key string."""
        return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')

    def generate_recovery_key(self) -> str:
        """Generates a 32-character hex Emergency Recovery Key."""
        return os.urandom(16).hex()

    def _derive_key(self, secret: str, salt: bytes) -> bytes:
        """Derives a Fernet-compatible key from a secret string and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        return base64.urlsafe_b64encode(kdf.derive(secret.encode()))

    def encrypt_envelope(self, target_secret: str, passkey: str) -> str:
        """Encrypts a secret (e.g. MVK) using a passkey (password or recovery key). Returns base64 payload."""
        salt = os.urandom(16)
        key = self._derive_key(passkey, salt)
        fernet = Fernet(key)
        encrypted_bytes = fernet.encrypt(target_secret.encode())
        payload = salt + encrypted_bytes
        return base64.b64encode(payload).decode('utf-8')

    def decrypt_envelope(self, envelope_b64: str, passkey: str) -> str:
        """Decrypts an envelope using passkey to retrieve secret (e.g. MVK)."""
        raw = base64.b64decode(envelope_b64.encode('utf-8'))
        salt = raw[:16]
        encrypted_bytes = raw[16:]
        key = self._derive_key(passkey, salt)
        fernet = Fernet(key)
        decrypted_bytes = fernet.decrypt(encrypted_bytes)
        return decrypted_bytes.decode('utf-8')

    def encrypt_data(self, data: dict, secret_key: str) -> bytes:
        """
        Encrypts a dictionary into a byte string using a secret key (MVK or password).
        Format: ENC:[16_byte_salt][encrypted_payload]
        """
        salt = os.urandom(16)
        key = self._derive_key(secret_key, salt)
        fernet = Fernet(key)
        
        json_str = json.dumps(data)
        encrypted_payload = fernet.encrypt(json_str.encode())
        
        return self.magic_header + salt + encrypted_payload

    def decrypt_data(self, file_content: bytes, secret_key: str) -> dict:
        """
        Decrypts bytes back into a dictionary using secret_key (MVK or password).
        Expects content to start with ENC:.
        """
        if not file_content.startswith(self.magic_header):
            raise ValueError("Invalid file format (missing magic header)")
            
        header_len = len(self.magic_header)
        salt = file_content[header_len : header_len + 16]
        encrypted_payload = file_content[header_len + 16 :]
        
        key = self._derive_key(secret_key, salt)
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

