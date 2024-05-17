import requests
from urllib.parse import urlparse, urljoin

def get_trusted_domains():
    api_key = '3d6a2ae51d943edd9e4e9668dd9fa689bc3fc3943bc1f9fe932413aac7c25648'
    url = 'https://www.virustotal.com/api/v3/domains?limit=100'
    headers = {
        'x-apikey': api_key 
    }

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json()
        domains = [item['id'] for item in data.get('data', [])]
        return domains
    else:
        return []

def is_open_redirect(url):
    trusted_domains = get_trusted_domains()

    parsed_url = urlparse(url)
    base_url = parsed_url.netloc

    if base_url not in trusted_domains:
        full_url = urljoin(url, '/')  # Ensure a valid URL for the request

        response = requests.get(full_url, allow_redirects=False)

        if response.status_code in [301, 302, 303, 307, 308]:
            redirect_url = response.headers.get('Location')
            if redirect_url:
                redirect_base_url = urlparse(redirect_url).netloc

                if redirect_base_url not in trusted_domains:
                    return f"The URL is vulnerable to open redirects. Original URL: {url}, Redirect URL: {redirect_url}"
    
    return f"The URL is not vulnerable to open redirects. Original URL: {url}"
