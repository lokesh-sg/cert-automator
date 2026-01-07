import os
import shutil
import zipfile
import json
import datetime

VERSION_FILE = "build_scripts/version_info.json"
SOURCE_DIR = "dev/app"
PROD_DIR = "prod/app"
VERSIONS_DIR = "code_backup" # Renamed from versions as per user request

def load_version():
    if os.path.exists(VERSION_FILE):
        with open(VERSION_FILE, 'r') as f:
            return json.load(f)
    return {"major": 1, "minor": 0, "build": 0}

def save_version(version):
    with open(VERSION_FILE, 'w') as f:
        json.dump(version, f, indent=4)

def increment_build(version):
    version['build'] += 1
    return version

def copy_source(version, source_path, output_dir):
    ver_str = f"v{version['major']}.{version['minor']}.0 Build {version['build']}"
    dest_path = os.path.join(output_dir, f"cert_automate_{ver_str}")
    
    if os.path.exists(dest_path):
        shutil.rmtree(dest_path)
        
    shutil.copytree(source_path, dest_path, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'venv', '.DS_Store'))
    return dest_path

def deploy_to_prod(source_path, prod_path):
    if os.path.exists(prod_path):
        shutil.rmtree(prod_path)
    shutil.copytree(source_path, prod_path, ignore=shutil.ignore_patterns('__pycache__', '*.pyc', 'venv', '.DS_Store'))

def main():
    print("Starting package process...")
    
    # 1. Load and increment version
    version = load_version()
    new_version = increment_build(version)
    save_version(new_version)
    
    ver_str = f"v{new_version['major']}.{new_version['minor']}.0 Build {new_version['build']}"
    print(f"Build version: {ver_str}")

    # 2. Archive to /code_backup (Unzipped)
    os.makedirs(VERSIONS_DIR, exist_ok=True)
    backup_path = copy_source(new_version, SOURCE_DIR, VERSIONS_DIR)
    print(f"Backed up code to: {backup_path}")

    # 3. Deploy to /prod
    deploy_to_prod(SOURCE_DIR, PROD_DIR)
    print(f"Deployed to: {PROD_DIR}")

    # 3.5 Copy version.json to app directories for runtime usage
    # We save a simplified {"version": "vX.Y_buildZ"} for easier parsing by app
    app_version_data = {"version": ver_str}
    with open(os.path.join(SOURCE_DIR, "version.json"), 'w') as f:
        json.dump(app_version_data, f)
    with open(os.path.join(PROD_DIR, "version.json"), 'w') as f:
        json.dump(app_version_data, f)
    print(" synced version.json to app directories.")

    # 4. Also copy Dockerfile to prod if not present or updated
    dev_dockerfile = "dev/Dockerfile"
    prod_dockerfile = "prod/Dockerfile"
    if os.path.exists(dev_dockerfile):
        shutil.copy2(dev_dockerfile, prod_dockerfile)
        print("Copied Dockerfile to prod.")
    
    # Copy docker-compose to prod if it doesn't exist, but usually prod config differs
    # We will copy dev template but user needs to edit it
    dev_compose = "dev/docker-compose.yml"
    prod_compose = "prod/docker-compose.yml"
    if not os.path.exists(prod_compose) and os.path.exists(dev_compose):
        shutil.copy2(dev_compose, prod_compose)
        print("Initialized prod/docker-compose.yml (Check configuration!)")

    print("[SUCCESS] Build and Deployment complete.")

if __name__ == "__main__":
    main()
