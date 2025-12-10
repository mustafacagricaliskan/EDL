def format_for_palo_alto(items):
    """
    Formats a list of items for Palo Alto EDL.

    Args:
        items (list): A list of items to format.

    Returns:
        str: A string with one item per line.
    """
    return "\n".join(items)

def format_for_fortinet(items):
    """
    Formats a list of items for Fortinet Fabric Connector.

    Args:
        items (list): A list of items to format.

    Returns:
        str: A string with one item per line, suitable for Fortinet.
    """
    # Fortinet's format is also one item per line, just like Palo Alto's
    return "\n".join(items)

