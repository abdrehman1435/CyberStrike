import requests
import re
import html

def check_url_for_xss(url):
    response = requests.get(url)

    # Check headers for potential XSS
    for header, value in response.headers.items():
        if re.search(r'<script.*?>', value, re.IGNORECASE):
            return f"Potential XSS in header '{header}': {url}"

    # Check URL parameters for potential XSS
    params = requests.utils.urlparse(url).query
    decoded_params = html.unescape(params)
    if re.search(r'<script.*?>', decoded_params, re.IGNORECASE):
        return f"Potential XSS in decoded URL parameters: {decoded_params} in {url}"

    # Check attribute values in the HTML content for potential XSS
    attribute_values = re.findall(r'\w+="(.*?)"', response.text)
    for value in attribute_values:
        decoded_value = html.unescape(value)
        if re.search(r'<script.*?>', decoded_value, re.IGNORECASE):
            return f"Potential XSS in decoded HTML attribute value: {decoded_value} in {url}"

    return f"The URL is not vulnerable to Cross-Site Scripting (XSS) attacks: {url}"

def crosssitescripting_result(url):
    return check_url_for_xss(url)