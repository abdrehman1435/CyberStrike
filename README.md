# RED TEAM WEB-EXPLOIT TOOLKIT

The cyberStrike repository is a comprehensive toolkit designed for conducting simulated cyber-attacks, specifically tailored for red team operations. 
It encompasses various scripts and tools to exploit vulnerabilities in web applications, networks, and systems.

## Overview

The CyberStrike project is a comprehensive toolkit designed for web exploitation, leveraging various Python libraries and frameworks such as Flask, Scapy, and BeautifulSoup to conduct a wide range of 
cyber security assessments. It includes functionalities like network scanning, packet sniffing, SQL injection detection, endpoint analysis, open redirect detection, cross-site scripting checks, 
HTTP security header inspection, TLS security assessment, and more. 

The application provides a graphical user interface for easy interaction, allowing users to execute different types of scans and view the results in a structured manner. Additionally, it supports 
capturing and logging keystrokes for further analysis, enhancing its capabilities for advanced penetration testing scenarios.

## Features

- **Network Scanning**: Identify active hosts and services across a network.
- **Packet Sniffing**: Capture and analyze network traffic for insights into communication patterns and potential exploits.
- **SQL Injection Detection**: Scan for SQL injection vulnerabilities in web applications.
- **Endpoint Analysis**: Analyze web endpoints for common security issues.
- **Open Redirect Detection**: Identify URLs that could lead to phishing or other attacks.
- **Cross-Site Scripting Checks**: Detect XSS vulnerabilities in web applications.
- **HTTP Security Header Inspection**: Evaluate the security posture of web servers.
- **TLS Security Assessment**: Assess the configuration and strength of TLS connections.
- **Keystroke Logging**: Capture and log keystrokes for deeper analysis.

## Getting Started

### Prerequisites

- Python 3.x
- Flask
- Scapy
- BeautifulSoup
- Requests
- Pynput
  
### Installation

To get started with the project, follow these steps:

1. Clone the repository:
```bash
git clone https://github.com/sakshay2318/cyberStrike.git
```
2. Navigate to the project directory:
```bash
cd CyberStrike
```
3. Install required Python packages:
```bash
pip install -r requirements.txt
```


### Usage

1. Run the Flask application:
```bash
python app.py
```

2. Access the toolkit through your web browser at `http://localhost:5000`.

## Contributing

Contributions to CyberStrike are welcome Please feel free to submit pull requests or report issues.

## License

CyberStrike is licensed under the MIT License. See the LICENSE file for details.

