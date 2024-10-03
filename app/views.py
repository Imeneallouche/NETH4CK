from flask import Flask, Blueprint, render_template, request, redirect, url_for, jsonify, Response
import psutil
import netifaces as ni
import threading
from scapy.all import sniff, IP
from . import socketio
import nmap
import logging
from flask_socketio import emit
import subprocess
import time

logging.basicConfig(level=logging.DEBUG)

main_bp = Blueprint('main', __name__)


#___________________________________________________
#                                                   |
#                   INDEX ROUTE                     |
#___________________________________________________|

@main_bp.route('/')
def index():
    return render_template("index.html")



#___________________________________________________
#                                                   |
#                 INTERFACES SCAN                   |
#  step 1: scan all available interfaces and their  |
#              config if they have any              |
#___________________________________________________|

@main_bp.route("/neth4ck")
def neth4ck():
    interfaces = []
    for interface_name, interface_addresses in psutil.net_if_addrs().items():
        ip_address = ''
        netmask = ''
        for address in interface_addresses:
            if address.family == ni.AF_INET:
                ip_address = address.address
                netmask = address.netmask
        interfaces.append({
            "name": interface_name,
            "ip_address": ip_address,
            "netmask": netmask,
        })
    return render_template("intercept.html", interfaces=interfaces)



#___________________________________________________
#                                                   |
#                INTERCEPT ROUTE                    |
#  step 2: user selects an interface for next step  |
#___________________________________________________|

@main_bp.route("/intercept", methods=["POST"])
def intercept():
    selected_interface = request.form.get('interface')
    return redirect(url_for('main.sniff_page', interface=selected_interface))



#___________________________________________________
#                                                   |
#               SNIFFING PACKETS PAGE               |
#___________________________________________________|

@main_bp.route("/sniff")
def sniff_page():
    interface = request.args.get('interface')
    return render_template("sniff.html", interface=interface)


#___________________________________________________
#                                                   |
#               THE GATEWAY CONFIGURATION           |
#  step 3 : find the IP address and netmask of      |
#             the gateway of the selected LAN       |
#___________________________________________________|

@main_bp.route("/available_ips")
def available_ips_page():
    gateway_ip = request.args.get('gateway_ip')
    return render_template("available_ips.html", gateway_ip=gateway_ip)

def sniff_packets(interface):
    stop_sniffing = threading.Event()

    def process_packet(packet):
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            if not is_private_ip(dst_ip):
                machine_ip = ni.ifaddresses(interface)[ni.AF_INET][0]['addr']
                machine_netmask = ni.ifaddresses(interface)[ni.AF_INET][0]['netmask']
                gateway_ip = ni.gateways()['default'][ni.AF_INET][0]
                gateway_netmask = machine_netmask  # Assuming a default netmask for simplicity
                socketio.emit('gateway_info', {
                    'machine_ip': machine_ip,
                    'machine_netmask': machine_netmask,
                    'gateway_ip': gateway_ip,
                    'gateway_netmask': gateway_netmask
                })
                stop_sniffing.set()
                return False  # Stop sniffing after the first packet
        return True

    sniff(iface=interface, prn=process_packet, store=0, stop_filter=lambda x: stop_sniffing.is_set())

def is_private_ip(ip):
    private_ips = [
        '10.', '172.16.', '172.17.', '172.18.', '172.19.',
        '172.20.', '172.21.', '172.22.', '172.23.', '172.24.',
        '172.25.', '172.26.', '172.27.', '172.28.', '172.29.',
        '172.30.', '172.31.', '192.168.'
    ]
    return any(ip.startswith(private_ip) for private_ip in private_ips)

def in_same_subnet(ip1, ip2, netmask):
    ip1_bin = ''.join([bin(int(x)+256)[3:] for x in ip1.split('.')])
    ip2_bin = ''.join([bin(int(x)+256)[3:] for x in ip2.split('.')])
    netmask_bin = ''.join([bin(int(x)+256)[3:] for x in netmask.split('.')])

    ip1_subnet = ''.join(['1' if ip1_bin[i] == netmask_bin[i] == '1' else '0' for i in range(32)])
    ip2_subnet = ''.join(['1' if ip2_bin[i] == netmask_bin[i] == '1' else '0' for i in range(32)])

    return ip1_subnet == ip2_subnet




#____________________________________________________
#                                                   |
#           IP SCAN FUNCTION USING NMAP             |
#  step 4 : scan occupied IP addresses in the LAN   | 
#                of selected interface              |
#___________________________________________________|

@socketio.on('start_ip_scan')
def handle_start_ip_scan(data):
    gateway_ip = data['gateway_ip']
    scan_network(gateway_ip)

def scan_network(gateway_ip):
    nm = nmap.PortScanner()
    # Calculate the /24 subnet
    ip_parts = gateway_ip.split('.')
    network = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"
    nm.scan(hosts=network, arguments='-sn')

    occupied_ips = []
    for host in nm.all_hosts():
        if 'up' in nm[host].state():
            occupied_ips.append(host)
            socketio.emit('occupied_ip', {'ip': host})

    # Emit signal when the scan is complete
    socketio.emit('scan_complete', {'occupied_ips': occupied_ips})




#____________________________________________
#                                           |
#         FREE IPs IN THE LAN               |
#  step 5: display non occupied IPs         |
#___________________________________________|

@main_bp.route("/free_ips")
def free_ips():
    gateway_ip = request.args.get("gateway_ip")
    occupied_ips_str = request.args.get("occupied_ips")
    occupied_ips = occupied_ips_str.split(',') if occupied_ips_str else []

    # Calculate the /24 subnet
    ip_parts = gateway_ip.split('.')
    base_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}."

    all_ips = [f"{base_ip}{i}" for i in range(1, 255)]
    free_ips = [ip for ip in all_ips if ip not in occupied_ips]

    return render_template("free_ips.html", free_ips=free_ips, gateway_ip=gateway_ip)



#_______________________________________________________
#                                                       |
#               CONFIGURATION OPTIONS                   |
#   step 6: give to user choice to choose  IP address   |
#              to assign statically to the machine      |
#_______________________________________________________|

@main_bp.route("/config_termination")
def config_termination():
    interface = request.args.get('interface')
    selected_ip = request.args.get('selected_ip')
    gateway_netmask = request.args.get('gateway_netmask')
    gateway_ip = request.args.get('gateway_ip')
    return render_template('config_termination.html', interface=interface, selected_ip=selected_ip, gateway_netmask=gateway_netmask, gateway_ip=gateway_ip)




#_______________________________________________________
#                                                       |
#           MACHINE STATIC CONFIGURATION                |
#   step 7: machine configuration using Linux commands  |
#_______________________________________________________|

@main_bp.route("/configure_ip", methods=["POST"])
def configure_ip():
    interface = request.form.get('interface')
    selected_ip = request.form.get('selected_ip')
    gateway_netmask = request.form.get('gateway_netmask')

    if not interface or not selected_ip or not gateway_netmask:
        return "Missing parameters", 400

    commands = [
        f"sudo ip addr flush dev {interface}",
        f"sudo ip addr add {selected_ip}/{gateway_netmask} dev {interface}",
        f"sudo ip link set {interface} up"
    ]

    for cmd in commands:
        subprocess.run(cmd, shell=True, check=True)

    return "Configuration complete", 200



#___________________________________________________
#                                                   |
#               CONFIGURATION CHECK                 |
#       step 8: Check configuration status          |
#___________________________________________________|

@main_bp.route('/check_configuration_status')
def check_configuration_status():
    # This route will be used to check the status of the configuration
    return jsonify({'status': 'done'})



#___________________________________________________________
#                                                           |
#                   NETWORK PENTESTING ROUTE                |
#  step 9: responder functionalities page to make network   |
#       pentesting on a specific PRECONFIGURED interface    |
#___________________________________________________________|

@main_bp.route('/network_pentesting')
def network_pentesting():
    interfaces = []
    for interface_name, interface_addresses in psutil.net_if_addrs().items():
        for address in interface_addresses:
            if address.family == ni.AF_INET:
                interfaces.append(interface_name)
    return render_template('netpentest.html', interfaces=interfaces)




#___________________________________________________
#                                                   |
#             RESPONDER CONFIGURATION               |
#      step 10: Configure responder functionality   |
#___________________________________________________|

# Route that handles form submissions from the HTML page
@main_bp.route('/configure_responder', methods=['POST'])
def configure_responder():
    # Get the selected network interface and local IP (for OSX)
    interface = request.form.get('interface')

    # List of the checkbox options from the form
    options = {
        "analyze": "-A",
        "httpAuth": "-b",
        "dhcp": "-d",
        "dhcpDns": "-D",
        "wpads" : "-w",
        "fwpad": "-F",
        "proxyAuth": "-P",
        "disableEss": "--disable-ess",
        "flmhashing": "--lm",
        "verbose": "-v",
    }
    
    # Functionalities that require input
    functionalities = {
        'uwpad': '-u',       # Upstream Proxy for WPAD
        'localIp': '-i',      # Local IP (for OSX)
        'externalIp6': '-6',  # Set External IPv6 Address
        'externalIp': '-e',   # Set External IP Address
    }

    # Initial Responder command with selected network interface
    responder_command = ["sudo", "python3", "Responder.py", "-I", interface]

    # Append options (flags) that don't require input
    for func in options:
        if request.form.get(func):
            responder_command.append(options[func])

    # Append functionalities that require input
    for func in functionalities:
        if request.form.get(func):
            responder_command.append(functionalities[func])  # Append the flag (e.g., -u)
            responder_command.append(request.form.get(func))  # Append the value (e.g., google:8080)

    # Output the command (for debugging purposes)
    print(f"command: {responder_command}")

    # Start the Responder process in the background
    responder_process = subprocess.Popen(responder_command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    # Stream the output to the terminal HTML page
    return Response(stream_output(responder_process), mimetype='text/plain')


def stream_output(process):
    """Function to stream the Responder output to the HTML page."""
    while True:
        output = process.stdout.readline()
        if output == b'' and process.poll() is not None:
            break
        if output:
            yield output.decode('utf-8')

@main_bp.route('/stop_responder', methods=['POST'])
def stop_responder():
    global responder_process
    if responder_process:
        responder_process.terminate()  # Terminate the process
        responder_process = None
        return jsonify({'message': 'Responder process stopped successfully.'})
    else:
        return jsonify({'error': 'Responder process is not running.'})

# Route to serve the HTML terminal page
@main_bp.route('/responder_terminal')
def responder_terminal():
    return render_template('terminal.html')


@socketio.on('start_sniff')
def handle_start_sniff(data):
    interface = data['interface']
    thread = threading.Thread(target=sniff_packets, args=(interface,))
    thread.start()