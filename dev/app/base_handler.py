from abc import ABC, abstractmethod
import logging

class CertificateHandler(ABC):
    def __init__(self, service_config: dict):
        self.config = service_config
        self.logger = logging.getLogger(f"CertAutomator.{service_config.get('name', 'Unknown')}")

    @abstractmethod
    def renew(self, cert_path: str, key_path: str) -> bool:
        """
        Renews the certificate for the service.
        
        Args:
            cert_path (str): Path to the new fullchain.pem file.
            key_path (str): Path to the new privkey.pem file.
            
        Returns:
            bool: True if renewal was successful, False otherwise.
        """
        return True

    def cleanup_expired(self) -> dict:
        """
        Optional: cleans up expired certificates for this service.
        Returns: {"success": bool, "message": str, "count": int}
        """
        return {"success": False, "message": "Cleanup not supported for this service", "count": 0}

    def check_remote_expiry(self) -> dict:
        """
        Checks the remote service's certificate expiration.
        Default implementation tries standard HTTPS (443).
        Override to specify different ports.
        """
        from .network_utils import check_ssl_expiry
        host = self.config.get('host')
        if not host:
            return {"success": False, "message": "No host configured"}
            
        # Determine port
        port = 443
        if self.config.get('check_port'):
            try: port = int(self.config.get('check_port'))
            except: pass
        elif self.config.get('port'):
            try: port = int(self.config.get('port'))
            except: pass
            
        return check_ssl_expiry(host, port=port)
