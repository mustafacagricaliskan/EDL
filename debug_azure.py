import requests
import re

url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
}

print(f"Fetching {url}...")
try:
    response = requests.get(url, headers=headers, timeout=15)
    print(f"Status Code: {response.status_code}")
    
    content = response.text
    print(f"Content Length: {len(content)}")
    
    # Try regex 1
    match1 = re.search(r'href="([^"]*ServiceTags_Public[^"]+\.json)"', content)
    if match1:
        print(f"Match 1 found: {match1.group(1)}")
    else:
        print("Match 1 failed.")
        
    # Try regex 2
    match2 = re.search(r'(https://download.microsoft.com/download/.*?\.json)', content)
    if match2:
        print(f"Match 2 found: {match2.group(1)}")
    else:
        print("Match 2 failed.")
        
    # Dump content to file for inspection if needed
    with open("azure_page_dump.html", "w", encoding="utf-8") as f:
        f.write(content)
        
except Exception as e:
    print(f"Error: {e}")
