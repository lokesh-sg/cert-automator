import os
import sys
import logging
import argparse
from .config_manager import ConfigManager
from .proxmox_handler import ProxmoxHandler
from .truenas_handler import TrueNASHandler
from .opnsense_handler import OPNSenseHandler
from .syncthing_handler import SyncthingHandler
from .wazuh_handler import WazuhHandler
from .heimdall_handler import HeimdallHandler
from .clearpass_handler import ArubaClearPassHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("cert_automate.log")
    ]
)
logger = logging.getLogger("CertAutomator.Main")

HANDLERS = {
    'proxmox': ProxmoxHandler,
    'truenas': TrueNASHandler,
    'opnsense': OPNSenseHandler,
    'syncthing': SyncthingHandler,
    'wazuh': WazuhHandler,
    'heimdall': HeimdallHandler,
    'clearpass': ArubaClearPassHandler,
    # 'portainer': PortainerHandler # Not implemented fully yet
}

def main():
    parser = argparse.ArgumentParser(description="Certificate Automation Tool")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    parser.add_argument("--cert-dir", default="../input_certificates", help="Directory containing fullchain.pem and privkey.pem")
    args = parser.parse_args()

    config_path = os.path.abspath(args.config)
    cert_dir = os.path.abspath(args.cert_dir)
    
    # Check certificate existence
    cert_path = os.path.join(cert_dir, "fullchain.pem")
    key_path = os.path.join(cert_dir, "privkey.pem")
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        logger.error(f"Certificates not found in {cert_dir}. Please place fullchain.pem and privkey.pem there.")
        sys.exit(1)

    logger.info(f"Using certificates from: {cert_dir}")
    
    # Load Config
    try:
        config_mgr = ConfigManager(config_path)
        config_mgr.load_config()
    except Exception as e:
        logger.critical(f"Failed to load config: {e}")
        sys.exit(1)

    services = config_mgr.get_services()
    if not services:
        logger.warning("No services defined in config.")
        return

    success_count = 0
    fail_count = 0

    for service in services:
        name = service.get('name')
        svc_type = service.get('type')
        enabled = service.get('enabled', True)
        
        if not enabled:
            logger.info(f"Skipping disabled service: {name}")
            continue

        handler_cls = HANDLERS.get(svc_type)
        if not handler_cls:
            logger.warning(f"Unknown service type '{svc_type}' for service '{name}'. Skipping.")
            continue

        logger.info(f"Processing service: {name} ({svc_type})...")
        try:
            handler = handler_cls(service)
            # Pass extra output_dir for ClearPass if needed, or handle inside renew
            # ClearPass handler checks config for output_dir
            if handler.renew(cert_path, key_path):
                logger.info(f"Successfully renewed certificate for {name}")
                success_count += 1
            else:
                logger.error(f"Failed to renew certificate for {name}")
                fail_count += 1
        except Exception as e:
            logger.exception(f"Unexpected error processing {name}: {e}")
            fail_count += 1

    logger.info(f"Batch complete. Success: {success_count}, Failed: {fail_count}")

if __name__ == "__main__":
    main()
