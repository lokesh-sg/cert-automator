
import logging
import requests
import json

class GenericWebhookHandler:
    @staticmethod
    def renew(service_config, cert_path, key_path, chain_path=None):
        logger = logging.getLogger("CertAutomator.WebhookHandler")
        
        # 1. Get Config
        url = service_config.get('url')
        method = service_config.get('method', 'POST').upper()
        headers_raw = service_config.get('headers', '{}')
        body_template = service_config.get('body_template', '{}')
        verify_ssl = service_config.get('verify_ssl', True)

        if not url:
            return {"success": False, "message": "URL is required for Webhook handler."}

        # 2. Load Cert Data
        try:
            with open(cert_path, 'r') as f: cert_pem = f.read()
            with open(key_path, 'r') as f: key_pem = f.read()
            chain_pem = ""
            if chain_path:
                with open(chain_path, 'r') as f: chain_pem = f.read()
        except Exception as e:
            return {"success": False, "message": f"Failed to read certificate files: {e}"}

        # 3. Prepare Payload (Template Substitution)
        # We replace {CERT}, {KEY}, {CHAIN} in the body_template string
        try:
            # Simple string replacement
            payload_str = body_template.replace('{CERT}', cert_pem)\
                                       .replace('{KEY}', key_pem)\
                                       .replace('{CHAIN}', chain_pem)
            
            # If headers imply JSON, we might want to ensure it's valid JSON?
            # Or we just send it as data/json depending on headers.
            # Users might want to send form-data too, but JSON is 95% of use cases.
            # Let's assume the user provides a valid JSON template if they want JSON.
            
            # Parse headers
            if isinstance(headers_raw, str):
                try:
                    headers = json.loads(headers_raw)
                except:
                    logger.warning("Invalid JSON in headers, using empty dict.")
                    headers = {}
            else:
                headers = headers_raw or {}

        except Exception as e:
            return {"success": False, "message": f"Template preparation failed: {e}"}

        # 4. Send Request
        try:
            # If content-type is json, we should probably send 'json=payload_dict' or 'data=payload_str'.
            # requests 'data' argument sends body bytes/str directly.
            
            logger.info(f"Sending {method} webhook to {url}")
            
            response = requests.request(
                method=method,
                url=url,
                headers=headers,
                data=payload_str, # Send the substituted string directly
                verify=verify_ssl,
                timeout=30
            )
            
            if response.status_code >= 200 and response.status_code < 300:
                return {"success": True, "message": f"Webhook successful: {response.status_code}"}
            else:
                return {"success": False, "message": f"Webhook failed: {response.status_code} - {response.text[:200]}"}

        except Exception as e:
            return {"success": False, "message": f"Webhook validation error: {e}"}
