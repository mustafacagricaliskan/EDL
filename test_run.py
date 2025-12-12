import requests
import warnings
from bs4 import BeautifulSoup

warnings.filterwarnings("ignore")

try:
    s = requests.Session()
    
    # 1. Get Login Page to get CSRF token for login form
    r = s.get('https://127.0.0.1/login', verify=False)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf_token_login = soup.find('input', {'name': 'csrf_token'})['value']
    
    # 2. Login
    login_data = {
        'username': 'admin',
        'password': '123456',
        'csrf_token': csrf_token_login
    }
    r = s.post('https://127.0.0.1/login', data=login_data, verify=False)
    print(f"Login status: {r.status_code}")

    # 3. Get Index Page to get CSRF Token for run action
    r = s.get('https://127.0.0.1/', verify=False)
    soup = BeautifulSoup(r.text, 'html.parser')
    csrf_meta = soup.find('meta', {'name': 'csrf-token'})
    if csrf_meta:
        csrf_token = csrf_meta['content']
        print(f"CSRF Token found: {csrf_token}")
        
        # 4. Trigger Run
        headers = {'X-CSRFToken': csrf_token}
        r = s.get('https://127.0.0.1/run', headers=headers, verify=False)
        print(f"Run status: {r.status_code}")
        print(f"Run response: {r.text}")
    else:
        print("CSRF Token meta tag not found!")

except Exception as e:
    print(f"Error: {e}")
