import json
import logging
import time
import requests

class DNSProviderBase:
    def __init__(self, config: dict):
        self.config = config
        self.logger = logging.getLogger(f"CertAutomator.DNS.{self.__class__.__name__}")

    def create_txt_record(self, domain: str, name: str, value: str) -> bool:
        """Create a TXT record for the ACME challenge."""
        raise NotImplementedError

    def delete_txt_record(self, domain: str, name: str, value: str):
        """Clean up the TXT record after the challenge."""
        raise NotImplementedError


class CloudflareDNSProvider(DNSProviderBase):
    def __init__(self, config: dict):
        super().__init__(config)
        self.api_token = self.config.get('api_token')
        self.base_url = "https://api.cloudflare.com/client/v4"
        self.headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }
        self.zone_id_cache = {}

    def _get_zone_id(self, domain: str) -> str:
        # For a given FQDN, find the root zone ID. Usually, we can search by base domain.
        # Strip subdomains to find the zone.
        parts = domain.split('.')
        for i in range(len(parts) - 1):
            root_domain = '.'.join(parts[i:])
            if root_domain in self.zone_id_cache:
                return self.zone_id_cache[root_domain]
                
            resp = requests.get(f"{self.base_url}/zones", headers=self.headers, params={"name": root_domain}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('success') and len(data.get('result', [])) > 0:
                    zone_id = data['result'][0]['id']
                    self.zone_id_cache[root_domain] = zone_id
                    return zone_id
                    
        raise ValueError(f"Could not determine Cloudflare Zone ID for {domain}")

    def create_txt_record(self, domain: str, name: str, value: str) -> bool:
        try:
            zone_id = self._get_zone_id(domain)
            payload = {
                "type": "TXT",
                "name": name,
                "content": value,
                "ttl": 120,
                "proxied": False # TXT records cannot be proxied anyway
            }
            resp = requests.post(f"{self.base_url}/zones/{zone_id}/dns_records", headers=self.headers, json=payload, timeout=10)
            data = resp.json()
            if resp.status_code == 200 and data.get('success'):
                self.logger.info(f"Successfully created TXT record {name} for {domain}")
                return True
            else:
                self.logger.error(f"Failed to create TXT record: {data}")
                return False
        except Exception as e:
            self.logger.exception(f"Exception creating TXT record on Cloudflare: {e}")
            return False

    def delete_txt_record(self, domain: str, name: str, value: str):
        try:
            zone_id = self._get_zone_id(domain)
            # Find the record ID first
            resp = requests.get(f"{self.base_url}/zones/{zone_id}/dns_records", headers=self.headers, params={"type": "TXT", "name": name, "content": value}, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                if data.get('success') and len(data.get('result', [])) > 0:
                    record_id = data['result'][0]['id']
                    # Delete it
                    del_resp = requests.delete(f"{self.base_url}/zones/{zone_id}/dns_records/{record_id}", headers=self.headers, timeout=10)
                    if del_resp.status_code == 200 and del_resp.json().get('success'):
                        self.logger.info(f"Successfully deleted TXT record {name} for {domain}")
                    else:
                        self.logger.warning(f"Failed to delete TXT record {record_id} on Cloudflare")
                else:
                    self.logger.warning(f"Could not find TXT record {name} with value {value} to delete")
            else:
                self.logger.warning(f"Failed to query TXT record {name} on Cloudflare for deletion")
        except Exception as e:
            self.logger.exception(f"Exception deleting TXT record on Cloudflare: {e}")

DNS_PROVIDERS = {
    "cloudflare": CloudflareDNSProvider
}

def get_dns_provider(provider_type: str, config: dict) -> DNSProviderBase:
    cls = DNS_PROVIDERS.get(provider_type)
    if not cls:
        raise ValueError(f"Unknown DNS provider: {provider_type}")
    return cls(config)
