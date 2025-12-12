import ipaddress
import logging

def is_ip_whitelisted(ip_str, whitelist_items):
    """
    Checks if an IP string is in the whitelist.
    whitelist_items: list of strings (IPs or CIDRs)
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not a valid IP, maybe a URL or domain.
        # If whitelist has exact string match, return True
        return ip_str in whitelist_items

    for item in whitelist_items:
        try:
            if '/' in item:
                # Check if IP matches CIDR
                network = ipaddress.ip_network(item, strict=False)
                if ip in network:
                    return True
            else:
                # Check exact IP match
                # Using ip_address object comparison handles IPv6 compression variations
                if ip == ipaddress.ip_address(item):
                    return True
        except ValueError:
             # Whitelist item might not be an IP/CIDR (e.g. domain), fallback to string match
            if ip_str == item:
                return True
            continue
            
    return False

def filter_whitelisted_items(items, whitelist_items):
    """
    Filters out items that are present in the whitelist.
    Returns a list of allowed items.
    """
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

    for item in items:
        try:
            ip = ipaddress.ip_address(item)
            # Check exact IPs first (fastest)
            if ip in exact_ips:
                continue
            
            # Check networks
            matched = False
            for net in networks:
                if ip in net:
                    matched = True
                    break
            if matched:
                continue
                
            allowed.append(item)

        except ValueError:
            # Not an IP, check string match
            if item in exact_strings:
                continue
            allowed.append(item)
            
    return allowed
