from .db_manager import get_all_indicators

def format_for_palo_alto(indicator_dict):
    """
    Formats a dictionary of indicators (from get_all_indicators) for Palo Alto EDL.
    Includes only 'ip' and 'cidr' types.

    Args:
        indicator_dict (dict): A dictionary of indicators with their details.

    Returns:
        str: A string with one IP/CIDR per line.
    """
    items = []
    for indicator, details in indicator_dict.items():
        if details.get('type') in ['ip', 'cidr']:
            items.append(indicator)
    return "\n".join(items)

def format_for_fortinet(indicator_dict):
    """
    Formats a dictionary of indicators (from get_all_indicators) for Fortinet Fabric Connector.
    Includes only 'ip' and 'cidr' types.

    Args:
        indicator_dict (dict): A dictionary of indicators with their details.

    Returns:
        str: A string with one IP/CIDR per line, suitable for Fortinet.
    """
    items = []
    for indicator, details in indicator_dict.items():
        if details.get('type') in ['ip', 'cidr']:
            items.append(indicator)
    return "\n".join(items)