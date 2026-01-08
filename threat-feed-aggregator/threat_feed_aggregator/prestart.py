import logging
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from threat_feed_aggregator.cert_manager import get_cert_paths, generate_self_signed_cert
from threat_feed_aggregator.app import init_db

# Configure minimal logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def prestart():
    logger.info("Running pre-start checks...")
    
    # 1. Initialize Database
    try:
        init_db()
        logger.info("Database initialized successfully.")
    except Exception as e:
        logger.error(f"Failed to initialize database: {e}")
        sys.exit(1)

    # 2. Ensure SSL Certificates Exist
    try:
        # generate_self_signed_cert checks if they exist internally
        cert_path, key_path = generate_self_signed_cert()
        logger.info(f"SSL Certificates verified at {cert_path}")
    except Exception as e:
        logger.error(f"Failed to verify/create certificates: {e}")
        sys.exit(1)

if __name__ == "__main__":
    prestart()
