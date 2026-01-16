import re
import requests
import ipaddress

# Copying the current regex and logic from parsers.py
URL_PATTERN = re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+")
# The updated regex I deployed
DOMAIN_PATTERN = re.compile(r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$")
IP_CANDIDATE_PATTERN = re.compile(r"^[0-9a-fA-F:./]+$")

def identify_indicator_type(indicator):
    indicator = indicator.strip()
    if not indicator:
        return "unknown"

    if IP_CANDIDATE_PATTERN.match(indicator):
        try:
            if '/' in indicator:
                ipaddress.ip_network(indicator, strict=False)
                return "cidr"
            else:
                ipaddress.ip_address(indicator)
                return "ip"
        except ValueError:
            pass

    if URL_PATTERN.match(indicator):
        return "url"

    if '/' in indicator and not indicator.startswith('/'):
        parts = indicator.split('/', 1)
        if DOMAIN_PATTERN.match(parts[0]):
            return "url"

    if DOMAIN_PATTERN.match(indicator):
         return "domain"

    return "unknown"

def test_usom():
    url = "https://www.usom.gov.tr/url-list.txt"
    print(f"Fetching {url}...")
    try:
        r = requests.get(url, timeout=15)
        content = r.text
        lines = content.splitlines()
        print(f"Fetched {len(lines)} lines.")
        
        unknown_count = 0
        domain_count = 0
        examples_unknown = []
        
        for line in lines:
            line = line.strip()
            if not line: continue
            
            itype = identify_indicator_type(line)
            if itype == "unknown":
                unknown_count += 1
                if len(examples_unknown) < 10:
                    examples_unknown.append(line)
            elif itype == "domain":
                domain_count += 1
                
        print(f"Results:")
        print(f"  Domains: {domain_count}")
        print(f"  Unknown: {unknown_count}")
        
        if examples_unknown:
            print("  First 10 Unknowns:")
            for ex in examples_unknown:
                print(f"    - '{ex}'")
                
    except Exception as e:
        print(f"Error fetching: {e}")

if __name__ == "__main__":
    test_usom()
