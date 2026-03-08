import socket
import ssl
import datetime
import logging

logger = logging.getLogger("CertAutomator.Network")

def check_ssl_expiry(host, port=443, timeout=5):
    """
    Connects to the host:port, retrieves the SSL certificate,
    and returns its expiration details.
    """
    # Handle host:port syntax
    if ':' in host and not host.startswith('['): # Simple IPv4 check
        parts = host.split(':')
        host = parts[0]
        try:
             port = int(parts[1])
        except: pass
    
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # We just want to see the cert, even if self-signed

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert(binary_form=True)
                # Parse binary cert using cryptography or ssl (if getpeercert() wasn't binary)
                # But CERT_NONE with binary_form=False returns empty dict usually.
                # So we must get binary and parse it, OR use binary_form=False with CERT_REQUIRED...
                # But valid certs might fail verification if we don't have the CA.
                # So we stick to binary_form=True and parse with cryptography.
                
                from cryptography import x509
                from cryptography.hazmat.backends import default_backend
                
                cert_obj = x509.load_der_x509_certificate(cert, default_backend())
                
                not_after = cert_obj.not_valid_after_utc
                now = datetime.datetime.now(datetime.timezone.utc)
                days_remaining = (not_after - now).days
                
                # Format
                return {
                    "success": True,
                    "expiry": not_after.strftime("%Y-%m-%d"),
                    "days_remaining": days_remaining,
                    "subject": cert_obj.subject.rfc4514_string(),
                    "issuer": cert_obj.issuer.rfc4514_string()
                }

    except Exception as e:
        logger.error(f"SSL Check Failed for {host}:{port}: {e}")
        return {
            "success": False,
            "message": str(e)
        }
