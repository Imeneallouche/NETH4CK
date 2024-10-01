import sys
import os
import thread
from servers.Browser import WorkstationFingerPrint, RequestType, RAPThisDomain, RapFinger
from SocketServer import UDPServer, ThreadingMixIn, BaseRequestHandler
from threading import Lock
import struct
from utils import *

# This variable will collect all the output for HTML rendering
output_data = []

def ParseRoles(data):
	if len(data) != 4:
		return ''

	AllRoles = {
		'Workstation':           (ord(data[0]) >> 0) & 1,
		'Server':                (ord(data[0]) >> 1) & 1,
		'SQL':                   (ord(data[0]) >> 2) & 1,
		'Domain Controller':     (ord(data[0]) >> 3) & 1,
		'Backup Controller':     (ord(data[0]) >> 4) & 1,
		'Time Source':           (ord(data[0]) >> 5) & 1,
		'Apple':                 (ord(data[0]) >> 6) & 1,
		'Novell':                (ord(data[0]) >> 7) & 1,
		'Member':                (ord(data[1]) >> 0) & 1,
		'Print':                 (ord(data[1]) >> 1) & 1,
		'Dialin':                (ord(data[1]) >> 2) & 1,
		'Xenix':                 (ord(data[1]) >> 3) & 1,
		'NT Workstation':        (ord(data[1]) >> 4) & 1,
		'WfW':                   (ord(data[1]) >> 5) & 1,
		'Unused':                (ord(data[1]) >> 6) & 1,
		'NT Server':             (ord(data[1]) >> 7) & 1,
		'Potential Browser':     (ord(data[2]) >> 0) & 1,
		'Backup Browser':        (ord(data[2]) >> 1) & 1,
		'Master Browser':        (ord(data[2]) >> 2) & 1,
		'Domain Master Browser': (ord(data[2]) >> 3) & 1,
		'OSF':                   (ord(data[2]) >> 4) & 1,
		'VMS':                   (ord(data[2]) >> 5) & 1,
		'Windows 95+':           (ord(data[2]) >> 6) & 1,
		'DFS':                   (ord(data[2]) >> 7) & 1,
		'Local':                 (ord(data[3]) >> 6) & 1,
		'Domain Enum':           (ord(data[3]) >> 7) & 1,
	}

	return ', '.join(k for k, v in AllRoles.items() if v == 1)


class BrowserListener(BaseRequestHandler):
	def handle(self):
		global output_data
		output_data = []  # Clear previous data

		data, socket = self.request

		lock = Lock()
		lock.acquire()

		DataOffset = struct.unpack('<H', data[139:141])[0]
		BrowserPacket = data[82+DataOffset:]
		ReqType = RequestType(BrowserPacket[0])

		Domain = Decode_Name(data[49:81])
		Name = Decode_Name(data[15:47])
		Role1 = NBT_NS_Role(data[45:48])
		Role2 = NBT_NS_Role(data[79:82])
		Fprint = WorkstationFingerPrint(data[190:192])
		Roles = ParseRoles(data[192:196])

		output_data.append(f"[BROWSER] Request Type : {ReqType}")
		output_data.append(f"[BROWSER] Address      : {self.client_address[0]}")
		output_data.append(f"[BROWSER] Domain       : {Domain}")
		output_data.append(f"[BROWSER] Name         : {Name}")
		output_data.append(f"[BROWSER] Main Role    : {Role1}")
		output_data.append(f"[BROWSER] 2nd Role     : {Role2}")
		output_data.append(f"[BROWSER] Fingerprint  : {Fprint}")
		output_data.append(f"[BROWSER] Role List    : {Roles}")

		RAPThisDomain(self.client_address[0], Domain)

		lock.release()

		return output_data


class ThreadingUDPServer(ThreadingMixIn, UDPServer):
	def server_bind(self):
		self.allow_reuse_address = 1
		UDPServer.server_bind(self)


def serve_thread_udp_broadcast(host, port, handler):
	try:
		server = ThreadingUDPServer(('', port), handler)
		server.serve_forever()
	except Exception as e:
		output_data.append(f"Error starting UDP server on port {port}: {e}")
		return output_data
