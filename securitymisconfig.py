import requests
def check_security_misconfiguration(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url)

        # Check for security misconfigurations
        vulnerabilities_detected = []

        if response.status_code == 200:
            # Check for sensitive headers
            sensitive_headers = ['server', 'x-powered-by']
            for header in sensitive_headers:
                if header in response.headers:
                    vulnerabilities_detected.append(f"Sensitive header '{header}' found.")

            # Check for directory listing
            if 'Index of /' in response.text:
                vulnerabilities_detected.append("Directory listing is enabled.")

        else:
            # Return a message indicating an error or inability to retrieve the URL
            return f"Error: Failed to retrieve the URL '{url}'."

        if vulnerabilities_detected:
            # Provide detailed information about the detected security misconfigurations
            details = "\n".join(vulnerabilities_detected)
            return f"Potential security misconfigurations detected on {url}:\n{details}"
        else:
            return f"No security misconfigurations detected on {url}"

    except requests.RequestException as e:
        # Return a message if an exception occurs during the request
        return f"Error: Request failed for URL '{url}' due to an exception: {str(e)}."