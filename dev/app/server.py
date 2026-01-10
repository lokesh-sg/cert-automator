from flask import Flask, request, jsonify, render_template, send_from_directory, session, redirect, url_for
from flask_wtf.csrf import CSRFProtect, generate_csrf
import os
import logging
from logging.handlers import RotatingFileHandler
import json
from .cert_manager import CertManager
from .cert_validator import CertValidator

app = Flask(__name__, static_folder='static', template_folder='templates')

# --- Security Configuration ---
# 1. Session & Secret Management
SECRET_ENV = os.getenv('FLASK_SECRET')
if not SECRET_ENV and os.getenv('NODE_ENV') == 'production':
    raise RuntimeError("Security Alert: FLASK_SECRET environment variable MUST be set in production mode.")
app.secret_key = SECRET_ENV or 'dev-fallback-secret-key-non-secure'

# 2. Strict Session Cookie Hardening
from datetime import timedelta
app.permanent_session_lifetime = timedelta(hours=2)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    SESSION_COOKIE_SECURE=os.getenv('USE_HTTPS', 'false').lower() == 'true',
)

# 3. Global CSRF Protection
csrf = CSRFProtect(app)

# 4. Initialize registry globally
app.temp_registry = {} 
# Note: Removed CORS(app) to enforce Same-Origin security. API is accessed from same domain.

# Configuration
def resolve_path(env_key, default_relative, docker_absolute=None):
    """
    Resolves a path with priority:
    1. Environment Variable (Explicit)
    2. Docker Mount Point (if exists & absolute)
    3. Local Relative Path (Default)
    """
    val = os.getenv(env_key)
    if val:
        return os.path.abspath(val)
    
    # Smart Fallback: Check if we are running in a container with standard mounts
    if docker_absolute and os.path.exists(docker_absolute) and os.path.isdir(docker_absolute):
        # Verify write access to be sure
        if os.access(docker_absolute, os.W_OK):
            return docker_absolute
            
    # Default to local relative path for Dev
    return os.path.abspath(default_relative)

CONFIG_PATH = os.path.abspath(os.getenv('CONFIG_PATH', 'config.yaml'))

# Certs: Env -> /certs (Docker) -> certs (Local)
CERT_DIR = resolve_path('CERT_DIR', 'certs', '/certs')

# Backups: Env -> /backup (Docker) -> backups (Local)
# Note: Docker Compose maps ./backup:/backup (Singular)
BACKUP_DIR = resolve_path('BACKUP_DIR', 'backups', '/backup')

_log_env = os.getenv('LOG_FILE')
if _log_env:
    LOG_FILE = os.path.abspath(_log_env)
else:
    # Logs: Docker maps ./logs:/app/logs, so default 'logs' in 'app' works for both if configured that way.
    # But usually LOG_DIR env is set.
    _log_dir = os.path.abspath(os.getenv('LOG_DIR', 'logs'))
    LOG_FILE = os.path.join(_log_dir, "cert_automate.log")

AUTH_FILE = os.path.abspath(os.getenv('AUTH_PATH', 'auth.json'))

def get_version():
    ver = "Dev Mode"
    try:
        v_path = os.path.join(os.path.dirname(__file__), "version.json")
        if os.path.exists(v_path):
             with open(v_path, 'r') as f:
                 ver = json.load(f).get("version", "Dev Mode")
    except: pass
    return ver

def is_auth_configured():
    """Checks if AUTH_FILE exists and contains valid JSON with a username."""
    if not os.path.exists(AUTH_FILE):
        return False
    try:
        with open(AUTH_FILE, 'r') as f:
            content = f.read().strip()
            if not content: return False
            data = json.loads(content)
            return bool(data.get('username'))
    except:
        return False

# Initialize Manager (Starts LOCKED unless env var provided)
master_password = os.getenv('MASTER_PASSWORD') # Initialize Cert Manager
logger = logging.getLogger(__name__)



app.cert_manager = CertManager(CONFIG_PATH, CERT_DIR, master_password=master_password, backup_dir=BACKUP_DIR)
# Restore backward compatibility for existing code references
manager = app.cert_manager

app.validator = CertValidator()
validator = app.validator

# 5. Runtime Security Tokens
import secrets
RESET_TOKEN = secrets.token_hex(16)
logging.info(f"--- SECURITY NOTICE ---")
logging.info(f"EMERGENCY RESET TOKEN: {RESET_TOKEN}")
logging.info(f"Use this token via API to reset system if password is forgotten.")
logging.info(f"-----------------------")

# Configure Logger to file
os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
file_handler = RotatingFileHandler(LOG_FILE, maxBytes=10*1024*1024, backupCount=5)
file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
root_logger = logging.getLogger()
root_logger.addHandler(file_handler)
root_logger.setLevel(logging.INFO)

# Startup Logs for Path Debugging
logger.info(f"--- PATH CONFIGURATION ---")
logger.info(f"CERT_DIR:   {CERT_DIR}")
logger.info(f"BACKUP_DIR: {BACKUP_DIR}")
logger.info(f"LOG_FILE:   {LOG_FILE}")
logger.info(f"CONFIG:     {CONFIG_PATH}")
logger.info(f"--------------------------")

# --- Middleware ---
@app.before_request
def check_auth():
    # Only allow static assets and core login/setup flow without auth
    WHITELIST = ['login', 'setup', 'do_login', 'do_setup', 'health_check', 'download_temp_file']
    if request.path.startswith('/static') or request.endpoint in WHITELIST:
        return
    
    # If auth doesn't exist (or is invalid/empty) -> Setup needed
    if not is_auth_configured():
        return redirect('/setup')

    # If Locked or Not Logged In
    if manager.is_locked or not session.get('logged_in'):
        if request.path.startswith('/api'):
             return jsonify({"success": False, "message": "Unauthorized / Locked"}), 401
        return redirect('/login')

# --- Routes ---

@app.route('/')
def index():
    return render_template('index.html', app_version=get_version())

@app.route('/setup', methods=['GET'], endpoint='setup')
def setup_page():
    if is_auth_configured():
         return redirect('/login')
    return render_template('setup.html', app_version=get_version())

@app.route('/login', methods=['GET'], endpoint='login')
def login_page():
     # If unlocked and logged in, go home
     if not manager.is_locked and session.get('logged_in'):
         return redirect('/')
     return render_template('login.html', app_version=get_version())

@app.route('/setup', methods=['POST'], endpoint='do_setup')
def do_setup():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({"success": False, "message": "Missing fields"}), 400
        
    # 1. Save Username
    with open(AUTH_FILE, 'w') as f:
        json.dump({"username": username}, f)
        
    # 2. Initialize Config (Encrypts it)
    if manager.unlock(password):
        # Save to ensure it exists and is encrypted
        manager.config_mgr.save_config()
        session.permanent = True
        session['logged_in'] = True
        session['username'] = username
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": "Failed to initialize config lock."}), 500

@app.route('/login', methods=['POST'], endpoint='do_login')
def do_login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    
    # 1. Verify Username
    if not is_auth_configured():
        return jsonify({"success": False, "message": "System not set up. Please go to /setup"}), 400
        
    with open(AUTH_FILE, 'r') as f:
        stored_auth = json.load(f)
        
    if stored_auth.get('username') != username:
         return jsonify({"success": False, "message": "Invalid Username"}), 401

    # 2. Attempt Unlock
    if manager.unlock(password):
        session.permanent = True # Enforce timeout
        session['logged_in'] = True
        session['username'] = username
        return jsonify({"success": True})
    else:
        return jsonify({"success": False, "message": "Invalid Password (Decryption Failed)"}), 401
        
@app.route('/api/reset', methods=['POST'])
def reset_system():
    # Only allow if explicitly confirmed or via some mechanism.
    # Since this is a "Forgot Password" flow, it's public but destructive.
    # We rely on physical access (localhost) or network access as the security barrier here.
    # In a real app, this would need email recovery or admin token.
    # For this "Hobby Project", we just require a JSON confirm flag.
    
    data = request.json
    confirm = data.get('confirm_reset')
    password = data.get('password')
    token = data.get('token')
    
    if not confirm:
         return jsonify({"success": False, "message": "Confirmation required"}), 400

    # 1. Verify either Master Password OR Emergency Token
    authenticated = False
    if password and manager.unlock(password):
        authenticated = True
    elif token and token == RESET_TOKEN:
        authenticated = True
        logging.warning("System reset triggered via Emergency Token!")
        
    if not authenticated:
        return jsonify({"success": False, "message": "Unauthorized reset. Invalid password or emergency token."}), 401

    try:
        import shutil
        import datetime
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Backup Config
        if os.path.exists(CONFIG_PATH):
            backup_conf = f"{CONFIG_PATH}.reset_backup_{timestamp}"
            shutil.copy2(CONFIG_PATH, backup_conf)
            os.remove(CONFIG_PATH)
            
        # Backup Auth
        if os.path.exists(AUTH_FILE):
             backup_auth = f"{AUTH_FILE}.reset_backup_{timestamp}"
             shutil.copy2(AUTH_FILE, backup_auth)
             os.remove(AUTH_FILE)
        
        # Also clear session
        session.clear()
        
        return jsonify({"success": True, "message": f"System reset. Config backed up to *.reset_backup_{timestamp}"})
    except Exception as e:
         return jsonify({"success": False, "message": f"Reset failed: {str(e)}"}), 500

@app.route('/api/change-password', methods=['POST'])
def change_password():
    if manager.is_locked:
        return jsonify({"success": False, "message": "System is locked"}), 401
        
    data = request.json
    current_password = data.get('current_password')
    new_password = data.get('new_password')
    
    if not current_password or not new_password:
        return jsonify({"success": False, "message": "Missing fields"}), 400
        
    # 1. Verify Current Password
    # Since we are unlocked, we can just compare with memory.
    # Note: manager.config_mgr.master_password IS the current password in memory.
    if current_password != manager.config_mgr.master_password:
        return jsonify({"success": False, "message": "Current password incorrect"}), 401
        
    try:
        # 2. Update Password in Memory
        manager.config_mgr.master_password = new_password
        
        # 3. Save (Re-encrypts with new password)
        manager.config_mgr.save_config()
        
        return jsonify({"success": True, "message": "Password updated successfully"})
    except Exception as e:
        # Revert on failure to be safe
        manager.config_mgr.master_password = current_password
        return jsonify({"success": False, "message": f"Update failed: {str(e)}"}), 500

@app.route('/logout')
def logout():
    session.clear()
    # We don't strictly "lock" the manager here to allow other concurrent sessions if we had them or background tasks,
    # BUT for this single-user app, we probably should LOCK it for security?
    # If we lock it, background scheduled tasks (if any) might fail.
    # Current scope: No background scheduler mentioned. So let's just clear session.
    # Actually user might expect logout to re-lock the vault.
    # manager.config_mgr.is_locked = True
    # Let's NOT lock the server process, just the session.
    return redirect('/login')


@app.route('/api/status', methods=['GET'])
def get_status():
    if manager.is_locked:
        return jsonify({"locked": True})
        
    services = manager.config_mgr.get_services()
    certs_ready = manager.check_certificates_ready()
    return jsonify({
        "locked": False,
        "certs_ready": certs_ready,
        "services": services,
        "is_unlocked": not manager.is_locked # redundancy for clarity
    })

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({"status": "healthy"})

@app.route('/api/renew/all', methods=['POST'])
def renew_all():
    results = manager.renew_all()
    return jsonify(results)

@app.route('/api/renew/<service_name>', methods=['POST'])
def renew_one(service_name):
    result = manager.renew_service(service_name)
    return jsonify(result)

@app.route('/api/check/<service_name>', methods=['POST'])
def check_service(service_name):
    result = manager.check_service_expiry(service_name)
    return jsonify(result)

@app.route('/api/cleanup/<service_name>', methods=['POST'])
def cleanup_service(service_name):
    result = manager.cleanup_service(service_name)
    return jsonify(result)

@app.route('/api/health-check', methods=['POST'])
def trigger_health_check():
    """Manually triggers the daily health check logic."""
    try:
        success = manager.perform_daily_health_check()
        return jsonify({"success": True, "message": "Health check triggered successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/upload', methods=['POST'])
def upload_certs():
    # Expected: 'cert', 'key', optional 'chain'
    if 'cert' not in request.files or 'key' not in request.files:
        return jsonify({"success": False, "message": "Missing Certificate or Private Key"}), 400
        
    cert_file = request.files['cert']
    key_file = request.files['key']
    
    # Handle chain parts
    chain_data = b""
    
    # Legacy 'chain' field
    if 'chain' in request.files and request.files['chain']:
        chain_data += request.files['chain'].read()
        
    # Discrete Inter/Root
    if 'inter' in request.files and request.files['inter']:
        cd = request.files['inter'].read()
        if cd:
            if chain_data and not chain_data.endswith(b'\n'): chain_data += b'\n'
            chain_data += cd
            
    if 'root' in request.files and request.files['root']:
        cd = request.files['root'].read()
        if cd:
            if chain_data and not chain_data.endswith(b'\n'): chain_data += b'\n'
            chain_data += cd
            
    if not chain_data: chain_data = None
    
    cert_data = cert_file.read()
    key_data = key_file.read()

    # 1. Load Object
    cert_obj = validator.load_cert(cert_data)
    if not cert_obj:
        return jsonify({"success": False, "message": "Invalid Certificate File (PEM format required)"}), 400

    key_obj = validator.load_key(key_data)
    if not key_obj:
         return jsonify({"success": False, "message": "Invalid Private Key File (PEM format required)"}), 400

    # 2. Key Match
    if not validator.validate_key_match(cert_obj, key_obj):
        return jsonify({"success": False, "message": "Private Key does NOT match the Certificate!"}), 400

    # 3. Chain
    full_chain_bytes = validator.combine_chain(cert_data, chain_data)

    # 4. Save
    try:
        os.makedirs(CERT_DIR, exist_ok=True)
        with open(os.path.join(CERT_DIR, 'fullchain.pem'), 'wb') as f:
            f.write(full_chain_bytes)
        with open(os.path.join(CERT_DIR, 'privkey.pem'), 'wb') as f:
            f.write(validator.normalize_pem(key_data))
    except Exception as e:
        return jsonify({"success": False, "message": f"Failed to save files: {e}"}), 500
    
    # 5. Get Details
    details = validator.get_cert_details(cert_obj)
    
    # Enrich details for UI inspection
    response_data = {
        "success": True, 
        "message": "Certificate Validated & Saved successfully",
        "details": {
            "chain_length": validator.count_chain(full_chain_bytes),
            "key_match": True,  # We validated this above at step 2
            "details": [details] # Wrap in list to match inspect format? Or frontend handles single object?
                                 # Frontend showModal line 1386: if (details.details) ... else ... single
                                 # It handles both structure.
                                 # But wait, line 1357 in JS: showModal(data.details, true);
                                 # inspect endpoint returns: { found: true, chain_length: N, key_match: T, details: [...] }
                                 # Here I am returning "details": details_object.
                                 # So in JS `data.details` is JUST the cert object.
                                 # I should match the structure expected by showModal.
        }
    }
    
    # Re-structuring response to match inspect format expected by showModal
    full_details_package = {
        "chain_length": validator.count_chain(full_chain_bytes),
        "key_match": True,
        # If we have a chain, we might want to return details for ALL certs in chain?
        # For now, let's just return the leaf details as single object or list?
        # validator.get_chain_details(full_chain_bytes) would be better.
        "details": validator.get_chain_details(full_chain_bytes)
    }

    return jsonify({
        "success": True, 
        "message": "Certificate Validated & Saved successfully",
        "details": full_details_package
    })

# --- Certificate Pack Management ---
@app.route('/api/certificates', methods=['GET'])
def list_certificates():
    packs = manager.list_cert_packs()
    return jsonify({"success": True, "packs": packs})

@app.route('/api/certificates/upload', methods=['POST'])
def upload_certificate_pack():
    if 'cert_file' not in request.files or 'key_file' not in request.files:
        return jsonify({"success": False, "message": "Missing certificate or key file"}), 400
        
    cert_file = request.files['cert_file']
    key_file = request.files['key_file']
    # Chain is optional (but recommended) - currently we append to cert_file if provided in UI logic
    # The current validator combines them, let's reuse validator logic if possible or just save raw?
    # Better to validate.
    
    from werkzeug.utils import secure_filename
    pack_name = secure_filename(request.form.get('name'))
    if not pack_name:
        return jsonify({"success": False, "message": "Valid Pack name required"}), 400

    try:
        cert_data = cert_file.read()
        key_data = key_file.read()
        
        # Validation
        cert_obj = validator.load_cert(cert_data)
        key_obj = validator.load_key(key_data)
        
        if not cert_obj or not key_obj:
             return jsonify({"success": False, "message": "Invalid Certificate or Key format"}), 400
             
        if not validator.validate_key_match(cert_obj, key_obj):
             return jsonify({"success": False, "message": "Private Key does not match Certificate"}), 400
             
        # Combine Chain (Leaf + [Inter] + [Root])
        full_chain = cert_data
        
        if 'inter_file' in request.files:
            inter_data = request.files['inter_file'].read()
            if inter_data:
                # Ensure newline separation
                if not full_chain.endswith(b'\n'): full_chain += b'\n'
                full_chain += inter_data
                
        if 'root_file' in request.files:
            root_data = request.files['root_file'].read()
            if root_data:
                # Ensure newline separation
                if not full_chain.endswith(b'\n'): full_chain += b'\n'
                full_chain += root_data
        
        saved_name = manager.save_cert_pack(pack_name, full_chain, key_data)
        return jsonify({"success": True, "message": f"Pack '{saved_name}' saved."})
        
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/certificates/<name>', methods=['DELETE'])
def delete_certificate_pack(name):
    try:
        if name == 'default':
             return jsonify({"success": False, "message": "Cannot delete default pack"}), 400
             
        if manager.delete_cert_pack(name):
            return jsonify({"success": True, "message": f"Pack '{name}' deleted."})
        else:
            return jsonify({"success": False, "message": "Pack not found"}), 404
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/cert/inspect', methods=['GET'])
@app.route('/api/cert/inspect', methods=['GET'])
def inspect_cert():
    pack_name = request.args.get('pack')
    
    try:
        cert_path, key_path = manager.get_cert_paths(pack_name)
    except Exception as e:
         return jsonify({"found": False, "message": str(e)})

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        return jsonify({"found": False, "message": f"No certificates found for pack '{pack_name or 'Default'}'."})
        
    try:
        with open(cert_path, 'rb') as f: cert_data = f.read()
        with open(key_path, 'rb') as f: key_data = f.read()
        
        cert_obj = validator.load_cert(cert_data)
        key_obj = validator.load_key(key_data)
        
        if not cert_obj or not key_obj:
             return jsonify({"found": True, "valid": False, "message": "Corrupted or Invalid PEM files"})
             
        match = validator.validate_key_match(cert_obj, key_obj)
        chain_len = validator.count_chain(cert_data)
        
        # Get details for ALL certs in the chain
        chain_details = validator.get_chain_details(cert_data)
        
        return jsonify({
            "found": True,
            "valid": True,
            "key_match": match,
            "chain_length": chain_len,
            "details": chain_details # Now a list
        })
    except Exception as e:
        return jsonify({"found": True, "valid": False, "message": str(e)})

@app.route('/api/services/add', methods=['POST'])
def add_service():
    try:
        data = request.json
        manager.config_mgr.add_service(data)
        return jsonify({"success": True, "message": "Service added successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

@app.route('/api/services/update', methods=['POST'])
def update_service():
    try:
        data = request.json
        name = data.get('name')
        if not name:
             return jsonify({"success": False, "message": "Service Name is required"}), 400
        
        # Split old_name from data if we are renaming
        original_name = data.get('original_name', name)
        
        # Remove original_name from data to not save it
        if 'original_name' in data:
            del data['original_name']

        manager.config_mgr.update_service(original_name, data)
        return jsonify({"success": True, "message": "Service updated successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

@app.route('/api/services/delete', methods=['POST'])
def delete_service():
    try:
        data = request.json
        name = data.get('name')
        manager.config_mgr.delete_service(name)
        return jsonify({"success": True, "message": "Service deleted successfully"})
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 400

@app.route('/api/provision', methods=['POST'])
def provision_credentials():
    try:
        data = request.json
        svc_type = data.get('type')
        host = data.get('host')
        user = data.get('user')
        password = data.get('password')
        
        if not all([svc_type, host, user, password]):
            return jsonify({"success": False, "message": "Missing required fields (type, host, user, password)"}), 400
            
        if svc_type == 'proxmox':
            from .proxmox_handler import ProxmoxHandler
            token_id, token_secret, node_name = ProxmoxHandler.provision_token(host, user, password)
            return jsonify({
                "success": True,
                "message": f"Token generated for node '{node_name}'",
                "credentials": {
                    "token_id": token_id,
                    "token_secret": token_secret,
                    "node": node_name
                }
            })
        elif svc_type == 'truenas':
            from .truenas_handler import TrueNASHandler
            api_key = TrueNASHandler.provision_api_key(host, user, password)
            return jsonify({
                "success": True,
                "message": "API Key generated successfully",
                "credentials": {
                    "api_key": api_key
                }
            })
        elif svc_type == 'portainer':
            from .portainer_handler import PortainerHandler
            jwt = PortainerHandler.provision_token(host, user, password)
            return jsonify({
                "success": True, 
                "message": "JWT Token retrieved successfully",
                "credentials": {
                    "access_token": jwt # naming it access_token for generic usage
                }
            })
        elif svc_type == 'opnsense':
            from .opnsense_handler import OPNSenseHandler
            key, secret = OPNSenseHandler.provision_api_key(host, user, password)
            return jsonify({
                "success": True,
                "message": "OPNsense API Key retrieved successfully",
                "credentials": {
                    "api_key": key,
                    "api_secret": secret
                }
            })
        else:
            return jsonify({"success": False, "message": f"Provisioning not supported for type: {svc_type}"}), 400
            
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500


@app.route('/api/types', methods=['GET'])
def get_types():
    try:
        # HANDLERS is imported at top level now (or we will add it)
        # But to be safe let's use the local import if top failed? 
        # No, let's fix top level.
        from .cert_manager import HANDLERS
        
        base_handlers = list(HANDLERS.keys())
        current_types = manager.config_mgr.get_service_types()
        
        return jsonify({
            'success': True,
            'types': current_types,
            'base_handlers': base_handlers
        })
    except Exception as e:
        import traceback
        logging.error(f"API Error /types: {e}\n{traceback.format_exc()}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/types', methods=['POST'])
def add_type():
    try:
        data = request.json
        name = data.get('name')
        base_handler = data.get('base_handler')
        
        if not name or not base_handler:
            return jsonify({'success': False, 'message': 'Name and base_handler required'}), 400
            
        manager.config_mgr.add_service_type(name, base_handler)
        return jsonify({'success': True, 'message': f"Service type '{name}' added"})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/types', methods=['DELETE'])
def delete_type():
    try:
        data = request.json
        name = data.get('name')
        
        if not name:
            return jsonify({'success': False, 'message': 'Name required'}), 400
            
        manager.config_mgr.remove_service_type(name)
        return jsonify({'success': True, 'message': f"Service type '{name}' deleted"})
    except ValueError as e:
        return jsonify({'success': False, 'message': str(e)}), 404
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/detect-paths', methods=['POST'])
def detect_paths():
    data = request.json
    svc_type = data.get('type')
    host = data.get('host')
    user = data.get('user')
    password = data.get('password')
    
    if not all([svc_type, host, user, password]):
        return jsonify({"success": False, "message": "Missing required fields"}), 400
        
    try:
        if svc_type == 'portainer':
            from .portainer_handler import PortainerHandler
            result = PortainerHandler.detect_paths(host, user, password)
            return jsonify({"success": True, "paths": result})
        else:
             return jsonify({"success": False, "message": "Detection not supported for this type"}), 400
    except Exception as e:
        return jsonify({"success": False, "message": str(e)}), 500

@app.route('/api/logs', methods=['GET'])
def get_logs():
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, 'r') as f:
            lines = f.readlines()
            # Return last 100 lines
            return jsonify({"logs": lines[-100:]})
    return jsonify({"logs": []})

@app.route('/api/download/<token>', defaults={'filename': None}, methods=['GET'])
@app.route('/api/download/<token>/<filename>', methods=['GET'])
def download_temp_file(token, filename):
    import time
    registry = getattr(app, 'temp_registry', {})
    file_info = registry.get(token)
    
    # 1. Token Validation & Expiry (Default 5 mins)
    if not file_info or time.time() > file_info.get('expires', 0):
        if token in registry: del registry[token]
        return jsonify({"success": False, "message": "Invalid or expired token"}), 404
        
    file_path = file_info.get('path')
    if not file_path or not os.path.exists(file_path):
        if token in registry: del registry[token]
        return jsonify({"success": False, "message": "File not found"}), 404
        
    # Security: Strict Path Normalization & Traversal Check
    file_path = os.path.abspath(file_path)
    # Ensure it's not a directory or sensitive system file
    if not os.path.isfile(file_path):
         return jsonify({"success": False, "message": "Access Denied"}), 403
         
    # Check if download is within allowed boundaries
    # (In this app: /tmp or the certs/ directory)
    allowed_dirs = [
        os.path.abspath('/tmp'),
        os.path.abspath(os.path.join(os.getcwd(), CERT_DIR)),
        os.path.abspath(os.path.join(os.getcwd(), BACKUP_DIR))
    ]
    
    is_safe = any(file_path.startswith(d) for d in allowed_dirs)
    if not is_safe:
        root_logger.warning(f"Security: Blocked download attempt outside allowed dirs: {file_path}")
        return jsonify({"success": False, "message": "Security Violation"}), 403
    
    # Auto-expunge token (One-Time-Use)
    del registry[token]
    
    directory = os.path.dirname(file_path)
    filename = os.path.basename(file_path)
    
    # Log size for debugging
    size = os.path.getsize(file_path)
    logging.info(f"Serving file {filename} ({size} bytes)")
    
    return send_from_directory(
        directory, 
        filename, 
        as_attachment=False, 
        mimetype='application/x-pkcs12'
    )


def start_scheduler():
    import time
    import threading
    import datetime
    
    def run_schedule():
        # WAIT FOR UNLOCK (System starts locked)
        while manager.is_locked:
            time.sleep(5) # Check every 5 seconds

        # Delay to ensure UI loads first (User Experience)
        time.sleep(10)

        # RUN ONCE ON STARTUP (After Unlock)
        try:
            root_logger.info("System Unlocked. Running initial Health & Expiry Check...")
            manager.perform_daily_health_check()
        except Exception as e:
            root_logger.error(f"Startup Health Check Failed: {e}")

        while True:
            # Simple polling every minute to see if time matches? Or calculate sleep?
            # User asked for "12:30 AM".
            # Calculate sleep duration
            now = datetime.datetime.now()
            target = now.replace(hour=0, minute=30, second=0, microsecond=0)
            if now >= target:
                target += datetime.timedelta(days=1)
            
            wait_seconds = (target - now).total_seconds()
            root_logger.info(f"Scheduler: Sleeping {wait_seconds:.0f}s until next check at {target}")
            
            time.sleep(wait_seconds)
            
            # Run Nightly
            try:
                root_logger.info("Scheduler: Running Nightly Health & Expiry Check...")
                manager.perform_daily_health_check()
            except Exception as e:
                root_logger.error(f"Scheduler Task Failed: {e}")

    t = threading.Thread(target=run_schedule, daemon=True)
    t.start()

# --- Scheduler Startup ---
# Ensure scheduler starts whether running via `python -m app.server` OR `gunicorn`
# In Gunicorn, __name__ is 'app.server', so __name__ == '__main__' is False.
if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or not app.debug:
    # Use a simple lock or flag to prevent double execution if multiple imports happen (rare here)
    if not getattr(app, '_scheduler_started', False):
        start_scheduler()
        app._scheduler_started = True

if __name__ == '__main__':
    # Initialize Registry
    app.temp_registry = {}
    
    # Port 5050 to avoid MacOS AirPlay conflict on 5000
    app.run(host='0.0.0.0', port=5050)
