import ipaddress
import logging

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG) # Set to DEBUG for this module

def is_ip_whitelisted(ip_str, whitelist_items):
    """
    Checks if an IP string (or CIDR) is in the whitelist.
    whitelist_items: list of strings (IPs or CIDRs)
    """
    logger.debug(f"Checking if {ip_str} is whitelisted against: {whitelist_items}")
    
    target = None
    is_network = False

    try:
        target = ipaddress.ip_address(ip_str)
    except ValueError:
        try:
            target = ipaddress.ip_network(ip_str, strict=False)
            is_network = True
        except ValueError:
            # Not a valid IP or CIDR
            pass

    if target is None:
        # String match fallback
        if ip_str in whitelist_items:
            logger.debug(f"'{ip_str}' matched exact string in whitelist.")
            return True
        return False

    for item in whitelist_items:
        try:
            if '/' in item:
                # Whitelist item is a CIDR
                wl_net = ipaddress.ip_network(item, strict=False)
                
                if is_network:
                    # Check if target network is a subnet of whitelist network OR overlaps
                    # Ideally we want to remove if it's FULLY contained.
                    if target.subnet_of(wl_net):
                        logger.debug(f"CIDR '{ip_str}' is subnet of whitelisted '{item}'.")
                        return True
                    if target == wl_net:
                        logger.debug(f"CIDR '{ip_str}' equals whitelisted '{item}'.")
                        return True
                else:
                    # Target is an IP
                    if target in wl_net:
                        logger.debug(f"IP '{ip_str}' in whitelisted CIDR '{item}'.")
                        return True
            else:
                # Whitelist item is an exact IP
                wl_ip = ipaddress.ip_address(item)
                if not is_network and target == wl_ip:
                    logger.debug(f"IP '{ip_str}' matched whitelisted IP '{item}'.")
                    return True
                
        except ValueError:
            continue
            
    logger.debug(f"'{ip_str}' not found in whitelist.")
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
