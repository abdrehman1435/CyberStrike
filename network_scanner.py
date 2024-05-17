import socket, threading

def check_status(ip, port_number, delay, output):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(delay)
    try:
        sock.connect((ip, port_number))
        output[port_number] = 'Open'
    except:
        output[port_number] = 'Close'

def scanner(ip, delay):
    threads = []       
    result = {}         
    port_range = 1024
  
    for i in range(port_range):
        t = threading.Thread(target=check_status, args=(ip, i, delay, result))
        threads.append(t)
    
    for i in range(port_range):
        threads[i].start()
   
    for i in range(port_range):
        threads[i].join()
   
    open_ports = []
    for i in range(port_range):
        if result[i] == 'Open':
            open_ports.append(i)
    return open_ports

def main(ip):
    delay = 0.25  
    open_ports = scanner(ip, delay)
    return open_ports

