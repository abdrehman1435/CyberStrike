import requests
def check_http_security_headers(url):
    try:
        response = requests.get(url)
        headers = response.headers

        secure_headers = ["Strict-Transport-Security", "Content-Security-Policy"]
        result_headers = []

        for header in secure_headers:
            if headers.get(header):
                result_headers.append(f"The website: has {header} header, indicating a secure configuration.")
            else:
                result_headers.append(f"The website does not have {header} header, which may indicate a less secure configuration.")

        if all(headers.get(header) for header in secure_headers):
            result_headers.append("The website is considered secure based on the required security headers.")
        else:
            result_headers.append("The website is considered not secure based on the absence of required security headers.")
        
        return result_headers

    except requests.exceptions.RequestException as e:
        return ["An error occurred:", str(e)]
