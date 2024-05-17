import ssl
import socket

def check_tls_security(url):
    try:
        hostname = url.split('//')[-1].split('/')[0]
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cipher = ssock.cipher()
                if cipher:
                    protocol = ssock.version()
                    key_exchange = ssock.shared_ciphers()
                    return f"The {url} is using a secure connection. Protocol: {protocol}, Cipher Name: {cipher[0]}, Cipher Version: {cipher[1]}, Cipher Bits: {cipher[2]}, Key Exchange: {key_exchange}"
                else:
                    return "The website is not using a secure cipher."

    except (ssl.SSLError, socket.error) as e:
        return f"An error occurred: {str(e)}"

url_to_check = 'https://www.google.com/'
result = check_tls_security(url_to_check)
print(result)
