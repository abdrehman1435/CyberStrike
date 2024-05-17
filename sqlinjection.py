import requests
from bs4 import BeautifulSoup as bs
from urllib.parse import urljoin

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.106 Safari/537.36"

def get_all_forms(url):
    soup = bs(s.get(url).content, "html.parser")
    return soup.find_all("form")

def get_form_details(form):
    details = {}
    try:
        action = form.attrs.get("action", None)
        if action:
            action = action.lower()
    except AttributeError:
        action = None

    # Get the form method (POST, GET, etc.)
    method = form.attrs.get("method", "get").lower()

    # Get all the input details such as type, name, and value
    inputs = []
    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        inputs.append({"type": input_type, "name": input_name, "value": input_value})

    # Store everything in the resulting dictionary
    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    
    return details


def is_vulnerable(response):
    """A simple boolean function that determines whether a page 
    is SQL Injection vulnerable from its response"""
    errors = {
        # MySQL
        "you have an error in your sql syntax;",
        "warning: mysql",
        # SQL Server
        "unclosed quotation mark after the character string",
        # Oracle
        "quoted string not properly terminated",
    }
    for error in errors:
        # if you find one of these errors, return True
        if error in response.content.decode().lower():
            return True
    # no error detected
    return False

def scan_sql_injection(url):
    # Check for SQL injection in the URL itself
    for c in "\"'":
        new_url = f"{url}{c}"
        res = s.get(new_url)
        if is_vulnerable(res):
            return f"SQL injection found in the URL. Payload: {new_url}"

    # Check for SQL injection in HTML forms
    forms = get_all_forms(url)
    for form in forms:
        form_details = get_form_details(form)
        for c in "\"'":
            data = {}
            for input_tag in form_details["inputs"]:
                if input_tag["value"] or input_tag["type"] == "hidden":
                    try:
                        data[input_tag["name"]] = input_tag["value"] + c
                    except:
                        pass
                elif input_tag["type"] != "submit":
                    data[input_tag["name"]] = f"test{c}"
            url = urljoin(url, form_details["action"])
            if form_details["method"] == "post":
                res = s.post(url, data=data)
            elif form_details["method"] == "get":
                res = s.get(url, params=data)
            if is_vulnerable(res):
                return f"SQL injection found in the HTML form(s). Form Action: {url}, Method: {form_details['method']}, Payload: {data}"

    # If no vulnerabilities are found, include the payload in the message
    payloads = [f"{input_name}: {input_value}" for input_name, input_value in data.items()]
    payload_message = ", ".join(payloads)
    return f"No SQL injection vulnerabilities found on {url}. Payloads tested: {payload_message}"
