
import os
import sys
# Add current dir to path
sys.path.append(os.getcwd())

from app.config_manager import ConfigManager

try:
    path = "config.yaml"
    if not os.path.exists(path):
        print("Config file not found")
        sys.exit(1)
        
    # Hack: Assuming we use the password from environment or just try to load if not encrypted?
    # Or assuming user has no password for dev?
    # If encrypted, this script needs the password.
    # I'll check if 'config.password' exists or similar? 
    # The server uses 'CONFIG_PASSWORD' env var potentially? Or just args.
    
    # Let's try to load without password first (Legacy/Plain)
    cm = ConfigManager(path)
    if cm.is_locked:
        print("Config LOCKED. Cannot verify without password.")
        # Try a common dev password? or check if I can see the file header.
    else:
        services = cm.get_services()
        print(f"Found {len(services)} services.")
        for s in services:
            print(f"Service: {s.get('name')}, Type: '{s.get('type')}'")
            
        types = cm.get_service_types()
        print("Service Types:", types)

except Exception as e:
    print(f"Error: {e}")
