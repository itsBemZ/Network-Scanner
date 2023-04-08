# python -m pip install --upgrade pip
# pip install python-nmap
# python app.py (for app only)
# python - m http.server 8000 & python app.py (app and localhost http://localhost:8000/)

import nmap
import time

network = '192.168.1.1/24'  # Replace with your network address
log_file = 'log.txt'  # Replace with the filename for your log file
html_file = 'index.html'  # Replace with the filename for your HTML file
ip_list_file = 'ip.txt'  # Replace with the filename for your IP list file

with open(ip_list_file, 'r') as f:
    ip_list = f.read().split()

def write_log(log_file, log_message):
    with open(log_file, 'a') as f:
        current_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
        log_line = f'{current_time} - {log_message}\n'
        f.write(log_line)

def scan_network(network):
    scanner = nmap.PortScanner()
    scanner.scan(hosts=network, arguments='-n -sP')
    hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
    online_ips = {host[0] for host in hosts_list if host[1] == 'up'}
    devices = []
    for ip in ip_list:
        if ip in online_ips:
            devices.append({'ip': ip, 'status': 'Online'})
        else:
            devices.append({'ip': ip, 'status': 'Offline'})
    return devices

def create_table(devices):
    table = '<table>\n'
    table += '<tr><th>IP</th><th>Status</th></tr>\n'
    for device in devices:
        if device['status'] == 'Online':
            status_style = 'style="background-color:green"'
        elif device['status'] == 'Offline':
            status_style = 'style="background-color:red"'
        table += f'<tr {status_style}><td>{device["ip"]}</td><td>{device["status"]}</td></tr>\n'
    table += '</table>\n'
    return table

def log(devices, current_devices):
    offline_devices = [d for d in devices if d['status'] == 'Online' and d not in current_devices]
    if len(offline_devices) > 0:
        for device in offline_devices:
            write_log(log_file, f'Device {device["ip"]} went offline')
    online_devices = [d for d in current_devices if d['status'] == 'Online' and d not in devices]
    if len(online_devices) > 0:
        for device in online_devices:
            write_log(log_file, f'Device {device["ip"]} came online')
    devices = current_devices

devices = scan_network(network)
while True:
    current_devices = scan_network(network)
    log(devices, current_devices)
    table = create_table(current_devices)
    with open(html_file, 'w') as f:
        f.write('<!DOCTYPE html>\n<html>\n<head>\n<meta http-equiv="refresh" content="2">\n<title>Network Scanner</title>\n<link rel="stylesheet" href="styles.css">\n</head>\n<body>\n')
        f.write(table)
        f.write('</body>\n</html>\n')
    devices = current_devices
    time.sleep(5)
