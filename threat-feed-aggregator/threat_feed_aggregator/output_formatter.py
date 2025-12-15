from .db_manager import get_all_indicators
from .utils import aggregate_ips

def format_for_palo_alto(indicator_dict):
    """
    Formats a dictionary of indicators (from get_all_indicators) for Palo Alto EDL.
    Includes only 'ip' and 'cidr' types, aggregated into CIDR blocks.

    Args:
        indicator_dict (dict): A dictionary of indicators with their details.

    Returns:
        str: A string with one IP/CIDR per line.
    """
    raw_items = []
    for indicator, details in indicator_dict.items():
        if details.get('type') in ['ip', 'cidr']:
            raw_items.append(indicator)
    
    # Optimize using CIDR aggregation
    aggregated_items = aggregate_ips(raw_items)
    
    return "\n".join(aggregated_items)

def format_for_fortinet(indicator_dict):
    """
    Formats a dictionary of indicators (from get_all_indicators) for Fortinet Fabric Connector.
    Includes only 'ip' and 'cidr' types, aggregated into CIDR blocks.

    Args:
        indicator_dict (dict): A dictionary of indicators with their details.

    Returns:
        str: A string with one IP/CIDR per line, suitable for Fortinet.
    """
    raw_items = []
    for indicator, details in indicator_dict.items():
        if details.get('type') in ['ip', 'cidr']:
            raw_items.append(indicator)
            
    # Optimize using CIDR aggregation
    aggregated_items = aggregate_ips(raw_items)

    return "\n".join(aggregated_items)

def format_for_url_list(indicator_dict):
    """
    Formats a dictionary of indicators for a URL/Domain list.
    Includes only 'url' and 'domain' types.

    Args:
        indicator_dict (dict): A dictionary of indicators with their details.

    Returns:
        str: A string with one URL/Domain per line.
    """
    items = []
    for indicator, details in indicator_dict.items():
        if details.get('type') in ['url', 'domain']:
            items.append(indicator)
    return "\n".join(items)

