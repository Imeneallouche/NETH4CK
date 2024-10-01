from utils import *
from SocketServer import BaseRequestHandler
from packets import FTPPacket

# This variable will collect all the output for HTML rendering
output_data = []

class FTP(BaseRequestHandler):
    def handle(self):
        global output_data
        output_data = []  # Reset the output data each time

        try:
            # Initial FTP response
            self.request.send(str(FTPPacket()))
            data = self.request.recv(1024)

            # Handle USER command
            if data[0:4] == "USER":
                User = data[5:].strip()
                Packet = FTPPacket(Code="331", Message="User name okay, need password.")
                self.request.send(str(Packet))
                data = self.request.recv(1024)

                # Log the user information for the output
                output_data.append(f"[*] [FTP] Received USER: {User}")

            # Handle PASS command
            if data[0:4] == "PASS":
                Pass = data[5:].strip()
                Packet = FTPPacket(Code="530", Message="User not logged in.")
                self.request.send(str(Packet))

                # Save credentials to the database
                SaveToDb({
                    'module': 'FTP',
                    'type': 'Cleartext',
                    'client': self.client_address[0],
                    'user': User,
                    'cleartext': Pass,
                    'fullhash': User + ':' + Pass
                })

                # Log the cleartext password for the output
                output_data.append(f"[*] [FTP] Received PASS: {Pass} for USER: {User}")

            # Handle unsupported commands
            else:
                Packet = FTPPacket(Code="502", Message="Command not implemented.")
                self.request.send(str(Packet))
                data = self.request.recv(1024)
                output_data.append("[*] [FTP] Unsupported command received")

        except Exception as e:
            output_data.append(f"Error in FTP handle: {e}")

        return output_data