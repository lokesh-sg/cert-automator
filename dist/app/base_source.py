from abc import ABC, abstractmethod
import logging
from typing import Dict, Any, Tuple, Optional

class CertificateSource(ABC):
    """
    Abstract Base Class for Certificate Sources.
    A Source is responsible for connecting to an external system (NPM, ACME, etc.)
    and pulling the latest fullchain.pem and privkey.pem for a specific domain/configuration.
    """
    def __init__(self, source_config: dict):
        self.config = source_config
        self.logger = logging.getLogger(f"CertAutomator.Source.{self.config.get('name', 'Unknown')}")

    @abstractmethod
    def pull_certificate(self) -> Dict[str, Any]:
        """
        Connects to the source, checks if an update is available/needed, and pulls the certificate.
        
        Returns a dictionary:
        {
            "success": bool,
            "message": str,
            "cert_data": bytes or None (the fullchain.pem payload),
            "key_data": bytes or None (the privkey.pem payload),
            "changed": bool (True if a new certificate was pulled)
        }
        """
        return {
            "success": False,
            "message": "Not implemented",
            "cert_data": None,
            "key_data": None,
            "changed": False
        }
