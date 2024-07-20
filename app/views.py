from flask import Blueprint, render_template, request, redirect, url_for
import psutil
import netifaces as ni
import threading
from scapy.all import sniff, IP
from . import socketio 

main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    return render_template("index.html")

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

@main_bp.route("/intercept", methods=["POST"])
def intercept():
    selected_interface = request.form.get('interface')
    return redirect(url_for('main.sniff_page', interface=selected_interface))

@main_bp.route("/sniff")
def sniff_page():
    interface = request.args.get('interface')
    return render_template("sniff.html", interface=interface)

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

@socketio.on('start_sniff')
def handle_start_sniff(data):
    interface = data['interface']
    thread = threading.Thread(target=sniff_packets, args=(interface,))
    thread.start()
