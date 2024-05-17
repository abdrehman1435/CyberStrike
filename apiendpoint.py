import requests
from bs4 import BeautifulSoup
import re
api_endpoints = ''

def extract_endpoints(url):
    response = requests.get(url)
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all URLs in the website's HTML
    urls = [a['href'] for a in soup.find_all('a', href=True)]

    # Extract API endpoints using a regular expression pattern
    pattern = r'(https?://[\w.-]+/\w+)'
    api_endpoints = [url for url in urls if re.match(pattern, url)]

    return api_endpoints

def is_secure(endpoint):
    if endpoint.startswith('https://'):
        return True
    else:
        return False

def find_secure_and_insecure_endpoints(endpoints):
    insecure_endpoints = []
    secure_endpoints = []
    for endpoint in endpoints:
        if not is_secure(endpoint):
            insecure_endpoints.append(endpoint)
        else:
            secure_endpoints.append(endpoint)
    
    return secure_endpoints, insecure_endpoints

def get_insecure_endpoints_message(insecure_endpoints):
    message = "Insecure API endpoints:\n"
    for endpoint in insecure_endpoints:
        message += f"- {endpoint}\n"
        message += "Solution: Consider using HTTPS to secure the endpoint.\n"
    return message

def get_secure_endpoints_message(secure_endpoints):
    message = "Secure API endpoints\n"
    for endpoint in secure_endpoints:
        message += f"- {endpoint}\n"
    return message

def analyze_endpoints(website_url):
    endpoints = extract_endpoints(website_url)
    if len(endpoints) == 0:
        return f"No API endpoints found on the website {website_url} \n\n {secure_message} "
    else:
        secure, insecure = find_secure_and_insecure_endpoints(endpoints)
        secure_message = get_secure_endpoints_message(secure)
        insecure_message = get_secure_endpoints_message(insecure)
        return f"All API endpoints found on the website  {website_url}\n\n {insecure_message} "
