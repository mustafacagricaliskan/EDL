import logging
import os
import redis

from apscheduler.jobstores.sqlalchemy import SQLAlchemyJobStore
from apscheduler.schedulers.background import BackgroundScheduler
from flask import Flask
from flask_wtf.csrf import CSRFProtect
from flask_session import Session

from .aggregator import fetch_and_process_single_feed
from .azure_services import process_azure_feeds
from .cert_manager import generate_self_signed_cert, get_ca_bundle_path, get_cert_paths
from .config_manager import DATA_DIR, read_config
from .db_manager import get_admin_password_hash, init_db, set_admin_password
from .database.schema import create_indexes_safely
from .github_services import process_github_feeds
from .log_manager import setup_memory_logging
from .microsoft_services import process_microsoft_feeds
from .version import __version__

# Initialize Memory Logging
setup_memory_logging()
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(name)s - %(message)s')

# Set CA Bundle if exists (for requests/aiohttp)
custom_ca_bundle = get_ca_bundle_path()
if custom_ca_bundle:
    os.environ['REQUESTS_CA_BUNDLE'] = custom_ca_bundle
    os.environ['SSL_CERT_FILE'] = custom_ca_bundle
    logging.info(f"Using custom CA bundle at: {custom_ca_bundle}")

from flask import Flask, request, g
import time
import threading

# ... (existing imports)

app = Flask(__name__)

# Background Thread for DB Optimization (Index Creation)
def run_db_optimization():
    time.sleep(10) # Wait 10s for Gunicorn to fully bind and app to settle
    logging.info("Triggering background DB optimization...")
    try:
        create_indexes_safely()
    except Exception as e:
        logging.error(f"DB Optimization failed: {e}")

threading.Thread(target=run_db_optimization, daemon=True).start()

@app.before_request
def start_timer():
    g.start = time.time()

@app.after_request
def log_request(response):
    if hasattr(g, 'start'):
        diff = time.time() - g.start
        if diff > 0.5: # Log slow requests > 500ms
            logging.warning(f"SLOW REQUEST: {request.method} {request.path} took {diff:.4f}s")
    return response

# Context processor to make version available to all templates
@app.context_processor
def inject_version():
    return dict(version=__version__)

# Validate Environment
SECRET_KEY = os.environ.get('SECRET_KEY')
ADMIN_PASSWORD_ENV = os.environ.get('ADMIN_PASSWORD')

if not SECRET_KEY:
    logging.error("Environment variable 'SECRET_KEY' is not set. Please set it for production use.")
    SECRET_KEY = 'dev_key_do_not_use_in_production'

app.secret_key = os.getenv('SECRET_KEY', 'default_secret_key')

# Jinja2 Filters
@app.template_filter('from_json')
def from_json_filter(value):
    import json
    try:
        return json.loads(value)
    except Exception:
        return {}

# CSRF Protection
csrf = CSRFProtect(app)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024

# Session Configuration
if os.environ.get('REDIS_HOST'):
    logging.info(f"Using Redis Session Interface ({os.environ['REDIS_HOST']})")
    app.config['SESSION_TYPE'] = 'redis'
    app.config['SESSION_REDIS'] = redis.from_url(f"redis://{os.environ['REDIS_HOST']}:{os.environ.get('REDIS_PORT', 6379)}")
else:
    logging.info("Using Filesystem Session Interface")
    app.config['SESSION_TYPE'] = 'filesystem'
    app.config['SESSION_FILE_DIR'] = os.path.join(DATA_DIR, 'flask_session')

app.config['SESSION_PERMANENT'] = False
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_COOKIE_SECURE'] = False 
app.config['SESSION_COOKIE_HTTPONLY'] = False
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

Session(app)

# Data Directory
if not os.path.exists(DATA_DIR):
    os.makedirs(DATA_DIR)

# Database
init_db()

# Admin Password Init
if ADMIN_PASSWORD_ENV:
    if not get_admin_password_hash():
        success, msg = set_admin_password(ADMIN_PASSWORD_ENV)
        if success:
            logging.info("Admin password initialized from ENV.")
        else:
            logging.error(f"Failed to set initial admin password: {msg}")

# Scheduler
from .scheduler_manager import scheduler, update_scheduled_jobs

# Ensure SSL
generate_self_signed_cert()

# Register Blueprints
from .routes import bp_api, bp_auth, bp_dashboard, bp_system
from .routes.tools import bp_tools
from .routes.analysis import bp_analysis

app.register_blueprint(bp_dashboard)
app.register_blueprint(bp_api) # Prefix /api
app.register_blueprint(bp_auth)
app.register_blueprint(bp_system)
app.register_blueprint(bp_tools)
app.register_blueprint(bp_analysis)

# Special Route handling to keep /status and /run compatible with existing JS
# Or we can simply add alias routes here
from .routes.api import run_script, status

app.add_url_rule('/status', view_func=status)
app.add_url_rule('/run', view_func=run_script)

# Start Scheduler
if not scheduler.running:
    scheduler.start()
    update_scheduled_jobs()

if __name__ == '__main__':
    cert_file, key_file = get_cert_paths()
    port = int(os.environ.get("PORT", 443))
    app.run(debug=True, use_reloader=False, ssl_context=(cert_file, key_file), host='0.0.0.0', port=port)
