import os
import time
from OpenSSL import crypto as ossl_crypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

import josepy as jose
from acme import client, messages, crypto_util, challenges

from .base_source import CertificateSource
from .dns_providers import get_dns_provider

class AcmeSource(CertificateSource):
    """
    Pulls certificates directly via ACME standard (Let's Encrypt / ZeroSSL).
    """
    def pull_certificate(self):
        provider_name = self.config.get('acme_provider', 'letsencrypt')
        domain = self.config.get('domain')
        email = self.config.get('email') or 'admin@example.com'
        dns_type = self.config.get('dns_provider', 'cloudflare')
        dns_token = self.config.get('dns_token')

        if not domain or not dns_token:
            return {"success": False, "message": "Domain and DNS token are required", "changed": False}

        DIRECTORY_URL = "https://acme-v02.api.letsencrypt.org/directory"
        if provider_name == 'zerossl':
            DIRECTORY_URL = "https://acme.zerossl.com/v2/DV90"
            # ZeroSSL typically requires EAB, which could be expanded later.
            
        self.logger.info(f"Starting native ACME pull for {domain} via {provider_name}")

        try:
            # 1. Generate Account Key
            acc_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            acc_key_pem = acc_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            jwk = jose.JWKRSA(key=acc_key)
            net = client.ClientNetwork(jwk, account=None)
            
            # 2. Register Account
            directory = messages.Directory.from_json(net.get(DIRECTORY_URL).json())
            client_acme = client.ClientV2(directory, net=net)
            
            regr = client_acme.new_account(
                messages.NewRegistration.from_data(
                    email=email.strip(), terms_of_service_agreed=True
                )
            )
            self.logger.info(f"Registered ACME account: {regr.uri}")

            # 3. Generate Domain Certificate Key & CSR
            # Use cryptography to generate private key, then OpenSSL for CSR because acme library uses OpenSSL format
            cert_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
            cert_key_pem = cert_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            req = ossl_crypto.X509Req()
            req.get_subject().CN = domain.encode('utf-8')
            
            # Note: For wildcard, the CN is typically the base domain, and wildcard is in SAN
            # Simplified here to just the requested domain
            ossl_key = ossl_crypto.load_privatekey(ossl_crypto.FILETYPE_PEM, cert_key_pem)
            req.set_pubkey(ossl_key)
            req.sign(ossl_key, "sha256")
            csr_pem = ossl_crypto.dump_certificate_request(ossl_crypto.FILETYPE_PEM, req)

            # 4. Create Order
            order = client_acme.new_order(csr_pem)
            
            # 5. Handle Authorizations and Challenges
            dns_provider = get_dns_provider(dns_type, {"api_token": dns_token})
            
            cleanup_records = []
            
            for authz in order.authorizations:
                # Find the DNS-01 challenge
                challb = None
                for c in authz.body.challenges:
                    if isinstance(c.chall, challenges.DNS01):
                        challb = c
                        break
                        
                if not challb:
                    return {"success": False, "message": "ACME server did not offer a DNS-01 challenge", "changed": False}

                # Construct the TXT record
                response, validation = challb.response_and_validation(client_acme.net.key)
                # domain for the challenge
                chall_domain = authz.body.identifier.value
                txt_name = f"_acme-challenge.{chall_domain}"

                self.logger.info(f"Deploying DNS-01 challenge {txt_name} = {validation}")
                success = dns_provider.create_txt_record(chall_domain, txt_name, validation)
                if not success:
                    return {"success": False, "message": "Failed to configure DNS challenge record", "changed": False}
                    
                cleanup_records.append((chall_domain, txt_name, validation))
                
            self.logger.info("Waiting 30 seconds for DNS propagation...")
            # Ideally poll DNS directly, but standard delay works for testing
            time.sleep(30)
            
            # 6. Answer Challenges
            for authz in order.authorizations:
                for c in authz.body.challenges:
                    if isinstance(c.chall, challenges.DNS01):
                        client_acme.answer_challenge(c, c.response(client_acme.net.key))
                        break
                        
            # 7. Finalize and wait for issuance
            # This triggers the ACME server to verify the DNS record
            try:
                finalized_order = client_acme.poll_and_finalize(order)
            except Exception as pe:
                self.logger.error(f"Failed to verify DNS challenge: {pe}")
                # Cleanup before returning
                for cd, tn, tv in cleanup_records:
                    dns_provider.delete_txt_record(cd, tn, tv)
                return {"success": False, "message": f"ACME Verification Failed: {pe}", "changed": False}

            # 8. Download Certificate
            cert_chain_pem = finalized_order.fullchain_pem.encode('utf-8')
            
            # 9. Cleanup DNS
            for cd, tn, tv in cleanup_records:
                dns_provider.delete_txt_record(cd, tn, tv)

            self.logger.info("Successfully fetched certificate via native ACME!")
            
            return {
                "success": True,
                "message": f"Native ACME strictly finalized for {domain}",
                "cert_data": cert_chain_pem,
                "key_data": cert_key_pem,
                "changed": True
            }

        except Exception as e:
            self.logger.exception("Native ACME Error")
            return {"success": False, "message": f"Native ACME Exception: {str(e)}", "changed": False}
