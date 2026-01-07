#!/bin/bash

# run_dev.sh
# Starts the CertAutomator development server from the Project Root context.
# This aligns file paths (certs/, backups/) with the Production structure.

# 1. Activate Virtual Environment (if exists)
if [ -f "dev/.venv_dev_stable/bin/activate" ]; then
    source dev/.venv_dev_stable/bin/activate
elif [ -f "dev/venv/bin/activate" ]; then
    source dev/venv/bin/activate
else
    echo "Warning: No virtual environment found. Attempting to run with system python..."
fi

# 2. Set Environment Variables
export PYTHONPATH=$(pwd)/dev
export CONFIG_PATH=dev/config.yaml
export AUTH_PATH=dev/auth.json
export CERT_DIR=certs
export BACKUP_DIR=backups
export FLASK_DEBUG=1
export FLASK_SECRET=dev-secret-key

# 3. Create directories if missing
mkdir -p certs
mkdir -p backups

echo "----------------------------------------"
echo "Starting CertAutomator (Dev Mode)"
echo "Context: $(pwd)"
echo "Config:  $CONFIG_PATH"
echo "Certs:   $CERT_DIR"
echo "Backups: $BACKUP_DIR"
echo "----------------------------------------"

# 4. Run Server (Module mode)
python3 -m app.server
