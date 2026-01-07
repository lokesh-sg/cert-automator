
import sys
import os

# Emulate running as python -m app.server
# We need to make sure 'app' is resolvable.
sys.path.append(os.getcwd())

try:
    from app.cert_manager import HANDLERS
    print("Import Successful:", list(HANDLERS.keys()))
except Exception as e:
    with open('error_log.txt', 'w') as f:
        import traceback
        f.write(traceback.format_exc())
    print("Import Failed - Check error_log.txt")
