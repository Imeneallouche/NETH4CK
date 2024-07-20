from flask import render_template, request, redirect, url_for, current_app as app
import psutil
import socket
from scapy.all import sniff, IP
from threading import Thread

from . import db
from .models import Todo


gateway_info = {"machine_ip": "", "machine_netmask": "", "gateway_ip": "", "gateway_netmask": ""}


@app.route('/neth4ck')
def neth4ck():
    interfaces = []
    for interface_name, interface_addresses in psutil.net_if_addrs().items():
        iface_info = {"name": interface_name, "ip_address": "", "netmask": ""}
        for address in interface_addresses:
            if address.family == socket.AF_INET:
                iface_info["ip_address"] = address.address
                iface_info["netmask"] = address.netmask
        interfaces.append(iface_info)
    return render_template('intercept.html', interfaces=interfaces)



@app.route('/intercept', methods=['POST'])
def intercept():
    selected_interface = request.form.get('interface')
    
    # Start a thread to sniff traffic on the selected interface
    thread = Thread(target=sniff_traffic, args=(selected_interface,))
    thread.start()

    return redirect(url_for('sniff', interface=selected_interface))


@app.route('/sniff')
def sniff():
    interface = request.args.get('interface')
    return render_template('sniff.html', interface=interface, gateway_info=gateway_info)



def sniff_traffic(interface):
    global gateway_info

    def packet_handler(packet):
        if IP in packet:
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            machine_ip = psutil.net_if_addrs()[interface][0].address
            machine_netmask = psutil.net_if_addrs()[interface][0].netmask
            if not in_same_subnet(src_ip, machine_ip, machine_netmask):
                gateway_info["machine_ip"] = machine_ip
                gateway_info["machine_netmask"] = machine_netmask
                gateway_info["gateway_ip"] = src_ip
                gateway_info["gateway_netmask"] = machine_netmask  # This would typically require additional logic to determine

    sniff(iface=interface, prn=packet_handler, store=False)

def in_same_subnet(ip1, ip2, netmask):
    ip1_bin = ''.join([bin(int(x)+256)[3:] for x in ip1.split('.')])
    ip2_bin = ''.join([bin(int(x)+256)[3:] for x in ip2.split('.')])
    netmask_bin = ''.join([bin(int(x)+256)[3:] for x in netmask.split('.')])

    ip1_subnet = ''.join(['1' if ip1_bin[i] == netmask_bin[i] == '1' else '0' for i in range(32)])
    ip2_subnet = ''.join(['1' if ip2_bin[i] == netmask_bin[i] == '1' else '0' for i in range(32)])

    return ip1_subnet == ip2_subnet



@app.route('/', methods=['POST', 'GET'])
def index():
    if request.method == "POST":
        task_content = request.form['content']
        new_task = Todo(content=task_content)

        try:
            db.session.add(new_task)
            db.session.commit()
            return redirect('/')
        except:
            return "There was an issue with adding your task"
    else:
        tasks = Todo.query.order_by(Todo.date_created).all()
        return render_template("index.html", tasks=tasks)







