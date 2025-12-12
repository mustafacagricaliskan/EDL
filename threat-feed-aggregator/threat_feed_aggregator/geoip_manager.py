import os
import logging
import geoip2.database

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) # Set to DEBUG for this module

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
GEOIP_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-Country.mmdb")

def get_country_code(ip_address):
    """
    Returns the ISO country code for an IP address.
    Returns 'Unknown' if DB not found or IP not found.
    """
    if not os.path.exists(GEOIP_DB_PATH):
        logger.debug(f"GeoIP DB not found at: {GEOIP_DB_PATH}")
        return None

    try:
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            logger.debug(f"Attempting GeoIP lookup for IP: {ip_address}")
            response = reader.country(ip_address)
            logger.debug(f"GeoIP result for {ip_address}: {response.country.iso_code}")
            return response.country.iso_code
    except geoip2.errors.AddressNotFoundError:
        logger.debug(f"GeoIP: IP address {ip_address} not found in database.")
        return None
    except Exception as e:
        logger.error(f"GeoIP lookup failed for {ip_address}: {e}")
        return None
