import ipaddress
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) # Set to DEBUG for this module

def is_ip_whitelisted(ip_str, whitelist_items):
    """
    Checks if an IP string is in the whitelist.
    whitelist_items: list of strings (IPs or CIDRs)
    """
    logging.debug(f"Checking if {ip_str} is whitelisted against: {whitelist_items}")
    
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not a valid IP, maybe a URL or domain.
        # If whitelist has exact string match, return True
        if ip_str in whitelist_items:
            logging.debug(f"'{ip_str}' matched exact string in whitelist.")
            return True
        return False

    for item in whitelist_items:
        try:
            if '/' in item:
                # Check if IP matches CIDR
                network = ipaddress.ip_network(item, strict=False)
                if ip in network:
                    logging.debug(f"'{ip_str}' matched CIDR '{item}' in whitelist.")
                    return True
            else:
                # Check exact IP match
                if ip == ipaddress.ip_address(item):
                    logging.debug(f"'{ip_str}' matched exact IP '{item}' in whitelist.")
                    return True
        except ValueError:
             # Whitelist item might not be an IP/CIDR (e.g. domain), fallback to string match
            if ip_str == item: # This path is for non-IP whitelist items against a non-IP item.
                               # It's less likely to be hit for IP_str input.
                logging.debug(f"'{ip_str}' matched non-IP string '{item}' in whitelist.")
                return True
            continue
            
    logging.debug(f"'{ip_str}' not found in whitelist.")
    return False

def filter_whitelisted_items(items, whitelist_items):
    """
    Filters out items that are present in the whitelist.
    Returns a list of allowed items.
    """
    logging.debug(f"Filtering {len(items)} items against {len(whitelist_items)} whitelist entries.")
    
    if not whitelist_items:
        return items

    allowed = []
    # Pre-process whitelist to separate networks and exact IPs for speed
    networks = []
    exact_ips = set()
    exact_strings = set()

    for w in whitelist_items:
        try:
            if '/' in w:
                networks.append(ipaddress.ip_network(w, strict=False))
            else:
                exact_ips.add(ipaddress.ip_address(w))
        except ValueError:
            exact_strings.add(w)
    
    logging.debug(f"Whitelist processed: {len(networks)} CIDRs, {len(exact_ips)} exact IPs, {len(exact_strings)} exact strings.")

    for item in items:
        try:
            ip = ipaddress.ip_address(item)
            # Check exact IPs first (fastest)
            if ip in exact_ips:
                logging.debug(f"Filtering out (exact IP match): {item}")
                continue
            
            # Check networks
            matched = False
            for net in networks:
                if ip in net:
                    logging.debug(f"Filtering out (CIDR match {net}): {item}")
                    matched = True
                    break
            if matched:
                continue
                
            allowed.append(item)

        except ValueError:
            # Not an IP, check string match
            if item in exact_strings:
                logging.debug(f"Filtering out (exact string match): {item}")
                continue
            allowed.append(item)
            
    logging.debug(f"Filtered to {len(allowed)} items.")
    return allowed
