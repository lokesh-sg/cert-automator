import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
import logging

class CertValidator:
    def __init__(self):
        self.logger = logging.getLogger("CertAutomator.Validator")

    def load_cert(self, data: bytes):
        try:
            return x509.load_pem_x509_certificate(data, default_backend())
        except Exception as e:
            self.logger.error(f"Failed to load certificate: {e}")
            return None

    def load_key(self, data: bytes):
        try:
            return serialization.load_pem_private_key(data, password=None, backend=default_backend())
        except Exception as e:
            self.logger.error(f"Failed to load private key: {e}")
            return None

    def validate_key_match(self, cert_obj, key_obj):
        """Checks if the private key matches the certificate's public key."""
        try:
            pub_key = cert_obj.public_key()
            
            # Sign a test message with private key
            # But simpler: compare public numbers if RSA
            if isinstance(key_obj, rsa.RSAPrivateKey):
                return key_obj.public_key().public_numbers() == pub_key.public_numbers()
            elif isinstance(key_obj, ec.EllipticCurvePrivateKey):
                return key_obj.public_key().public_numbers() == pub_key.public_numbers()
            
            # Fallback for others (like Ed25519) - sign/verify check is more robust but complex
            # For this MVP, we assume RSA/EC
            return False
        except Exception as e:
            self.logger.error(f"Key match validation failed: {e}")
            return False

    def get_cert_details(self, cert_obj):
        try:
            subject = cert_obj.subject.rfc4514_string()
            issuer = cert_obj.issuer.rfc4514_string()
            not_after = cert_obj.not_valid_after_utc
            
            sans = []
            try:
                ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                sans = ext.value.get_values_for_type(x509.DNSName)
            except x509.ExtensionNotFound:
                pass
            
            now = datetime.datetime.now(datetime.timezone.utc)
            days_remaining = (not_after - now).days
            
            return {
                "subject": subject,
                "issuer": issuer,
                "serial_number": str(cert_obj.serial_number),
                "version": cert_obj.version.name,
                "signature_algorithm": cert_obj.signature_algorithm_oid._name,
                "expiry": not_after.isoformat(),
                "days_remaining": days_remaining,
                "sans": sans
            }
        except Exception as e:
            self.logger.error(f"Failed to parse details: {e}")
            return {}

    def normalize_pem(self, data: bytes) -> bytes:
        """Ensures PEM has correct newlines."""
        s = data.decode('utf-8').strip()
        return (s + "\n").encode('utf-8')

    def get_chain_details(self, data: bytes) -> list:
        """Parses all certificates in the chain and returns details for each."""
        try:
            certs = x509.load_pem_x509_certificates(data)
            return [self.get_cert_details(c) for c in certs]
        except Exception as e:
            self.logger.error(f"Failed to load chain details: {e}")
            return []

    def count_chain(self, data: bytes) -> int:
        """Counts the number of certificates in the chain."""
        try:
            content = data.decode('utf-8')
            return content.count("BEGIN CERTIFICATE")
        except Exception:
            return 0

    def combine_chain(self, cert_bytes: bytes, chain_bytes: bytes = None) -> bytes:
        """Combines Certificate and optional Chain into a Full Chain."""
        # Clean inputs
        full = self.normalize_pem(cert_bytes)
        if chain_bytes:
            full += self.normalize_pem(chain_bytes)
        return full
