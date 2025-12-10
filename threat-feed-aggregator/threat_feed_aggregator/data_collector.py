import requests

def fetch_data_from_url(url):
    """
    Fetches data from a given URL.

    Args:
        url (str): The URL to fetch data from.

    Returns:
        str: The content of the response, or None if the request fails.
    """
    try:
        response = requests.get(url)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.text
    except requests.exceptions.RequestException as e:
        print(f"Error fetching data from {url}: {e}")
        return None
