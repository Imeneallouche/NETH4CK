from utils import *
from base64 import b64decode
from SocketServer import BaseRequestHandler
from packets import SMTPGreeting, SMTPAUTH, SMTPAUTH1, SMTPAUTH2

# This variable will collect all the output for HTML rendering
output_data = []

class ESMTP(BaseRequestHandler):
    def handle(self):
        global output_data
        output_data = []  # Clear previous data

        try:
            self.request.send(str(SMTPGreeting()))
            output_data.append(f"[SMTP] Sent greeting to {self.client_address[0]}")
            data = self.request.recv(1024)

            if data[0:4] == "EHLO":
                self.request.send(str(SMTPAUTH()))
                output_data.append(f"[SMTP] Received EHLO from {self.client_address[0]}")
                data = self.request.recv(1024)

            if data[0:4] == "AUTH":
                self.request.send(str(SMTPAUTH1()))
                output_data.append(f"[SMTP] Received AUTH from {self.client_address[0]}")
                data = self.request.recv(1024)

                if data:
                    try:
                        User = filter(None, b64decode(data).split('\x00'))
                        Username = User[0]
                        Password = User[1]
                        output_data.append(f"[SMTP] Decoded username and password for {self.client_address[0]}: {Username}:{Password}")
                    except:
                        Username = b64decode(data)
                        self.request.send(str(SMTPAUTH2()))
                        output_data.append(f"[SMTP] Sent AUTH1 to {self.client_address[0]}")
                        data = self.request.recv(1024)

                        if data:
                            try:
                                Password = b64decode(data)
                            except:
                                Password = data
                            output_data.append(f"[SMTP] Decoded password for {self.client_address[0]}: {Password}")

                    SaveToDb({
                        'module': 'SMTP',
                        'type': 'Cleartext',
                        'client': self.client_address[0],
                        'user': Username,
                        'cleartext': Password,
                        'fullhash': Username + ":" + Password,
                    })
                    output_data.append(f"[SMTP] Credentials saved for {self.client_address[0]}: {Username}:{Password}")

        except Exception as e:
            output_data.append(f"[SMTP] Error: {str(e)}")

        return output_data
