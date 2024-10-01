from packets import SMBHeader, SMBNegoData, SMBSessionData, SMBTreeConnectData, RAPNetServerEnum3Data, SMBTransRAPData
from SocketServer import BaseRequestHandler
from utils import *
import struct

# This variable will collect all the output for HTML rendering
output_data = []

def WorkstationFingerPrint(data):
    return {
        "\x04\x00": "Windows 95",
        "\x04\x10": "Windows 98",
        "\x04\x90": "Windows ME",
        "\x05\x00": "Windows 2000",
        "\x05\x01": "Windows XP",
        "\x05\x02": "Windows XP(64-Bit)/Windows 2003",
        "\x06\x00": "Windows Vista/Server 2008",
        "\x06\x01": "Windows 7/Server 2008R2",
        "\x06\x02": "Windows 8/Server 2012",
        "\x06\x03": "Windows 8.1/Server 2012R2",
        "\x10\x00": "Windows 10/Server 2016",
    }.get(data, 'Unknown')


def RequestType(data):
    return {
        "\x01": 'Host Announcement',
        "\x02": 'Request Announcement',
        "\x08": 'Browser Election',
        "\x09": 'Get Backup List Request',
        "\x0a": 'Get Backup List Response',
        "\x0b": 'Become Backup Browser',
        "\x0c": 'Domain/Workgroup Announcement',
        "\x0d": 'Master Announcement',
        "\x0e": 'Reset Browser State Announcement',
        "\x0f": 'Local Master Announcement',
    }.get(data, 'Unknown')


def PrintServerName(data, entries):
    if entries <= 0:
        return None
    entrieslen = 26 * entries
    chunks, chunk_size = len(data[:entrieslen]), entrieslen // entries
    ServerName = [data[i:i + chunk_size] for i in range(0, chunks, chunk_size)]

    l = []
    for x in ServerName:
        fingerprint = WorkstationFingerPrint(x[16:18])
        name = x[:16].replace('\x00', '')
        l.append('%s (%s)' % (name, fingerprint))
    return l


def ParsePacket(Payload):
    PayloadOffset = struct.unpack('<H', Payload[51:53])[0]
    StatusCode = Payload[PayloadOffset - 4:PayloadOffset - 2]

    if StatusCode == "\x00\x00":
        EntriesNum = struct.unpack('<H', Payload[PayloadOffset:PayloadOffset + 2])[0]
        return PrintServerName(Payload[PayloadOffset + 4:], EntriesNum)
    return None


def RAPThisDomain(Client, Domain):
    pdc_list, sql_list, wkst_list = [], [], []
    
    PDC = RapFinger(Client, Domain, "\x00\x00\x00\x80")
    if PDC is not None:
        pdc_list.append(f"Detected Domains: {', '.join(PDC)}")

    SQL = RapFinger(Client, Domain, "\x04\x00\x00\x00")
    if SQL is not None:
        sql_list.append(f"Detected SQL Servers on domain {Domain}: {', '.join(SQL)}")

    WKST = RapFinger(Client, Domain, "\xff\xff\xff\xff")
    if WKST is not None:
        wkst_list.append(f"Detected Workstations/Servers on domain {Domain}: {', '.join(WKST)}")

    return pdc_list, sql_list, wkst_list


def RapFinger(Host, Domain, Type):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((Host, 445))
        s.settimeout(0.3)

        Header = SMBHeader(cmd="\x72", mid="\x01\x00")
        Body = SMBNegoData()
        Body.calculate()

        Packet = str(Header) + str(Body)
        Buffer = struct.pack(">i", len(''.join(Packet))) + Packet

        s.send(Buffer)
        data = s.recv(1024)

        if data[8:10] == "\x72\x00":  # Session Setup AndX Request, Anonymous.
            Header = SMBHeader(cmd="\x73", mid="\x02\x00")
            Body = SMBSessionData()
            Body.calculate()

            Packet = str(Header) + str(Body)
            Buffer = struct.pack(">i", len(''.join(Packet))) + Packet

            s.send(Buffer)
            data = s.recv(1024)

            if data[8:10] == "\x73\x00":  # Tree Connect IPC$.
                Header = SMBHeader(cmd="\x75", flag1="\x08", flag2="\x01\x00", uid=data[32:34], mid="\x03\x00")
                Body = SMBTreeConnectData(Path="\\\\" + Host + "\\IPC$")
                Body.calculate()

                Packet = str(Header) + str(Body)
                Buffer = struct.pack(">i", len(''.join(Packet))) + Packet

                s.send(Buffer)
                data = s.recv(1024)

                if data[8:10] == "\x75\x00":  # Rap ServerEnum.
                    Header = SMBHeader(cmd="\x25", flag1="\x08", flag2="\x01\xc8", uid=data[32:34], tid=data[28:30], pid=data[30:32], mid="\x04\x00")
                    Body = SMBTransRAPData(Data=RAPNetServerEnum3Data(ServerType=Type, DetailLevel="\x01\x00", TargetDomain=Domain))
                    Body.calculate()

                    Packet = str(Header) + str(Body)
                    Buffer = struct.pack(">i", len(''.join(Packet))) + Packet

                    s.send(Buffer)
                    data = s.recv(64736)

                    if data[8:10] == "\x25\x00":  # Rap ServerEnum, Get answer and return what we're looking for.
                        s.close()
                        return ParsePacket(data)
    except Exception as e:
        output_data.append(f"Error in RapFinger: {e}")
        return None


def BecomeBackup(data, Client):
    try:
        DataOffset = struct.unpack('<H', data[139:141])[0]
        BrowserPacket = data[82 + DataOffset:]
        ReqType = RequestType(BrowserPacket[0])

        if ReqType == "Become Backup Browser":
            ServerName = BrowserPacket[1:]
            Domain = Decode_Name(data[49:81])
            Name = Decode_Name(data[15:47])
            Role = NBT_NS_Role(data[45:48])

            if settings.Config.AnalyzeMode:
                result = (f"[Analyze mode: Browser] Datagram Request from IP: {Client} hostname: {Name} via the: {Role} "
                          f"wants to become a Local Master Browser Backup on this domain: {Domain}.")
                output_data.append(result)
                pdc, sql, wkst = RAPThisDomain(Client, Domain)
                output_data.extend(pdc + sql + wkst)

    except Exception as e:
        output_data.append(f"Error in BecomeBackup: {e}")


def ParseDatagramNBTNames(data, Client):
    try:
        Domain = Decode_Name(data[49:81])
        Name = Decode_Name(data[15:47])
        Role1 = NBT_NS_Role(data[45:48])
        Role2 = NBT_NS_Role(data[79:82])

        if Role2 in ["Domain Controller", "Browser Election", "Local Master Browser"] and settings.Config.AnalyzeMode:
            result = (f"[Analyze mode: Browser] Datagram Request from IP: {Client} hostname: {Name} via the: {Role1} "
                      f"to: {Domain}. Service: {Role2}")
            output_data.append(result)
            pdc, sql, wkst = RAPThisDomain(Client, Domain)
            output_data.extend(pdc + sql + wkst)

    except Exception as e:
        output_data.append(f"Error in ParseDatagramNBTNames: {e}")


class Browser(BaseRequestHandler):

    def handle(self):
        global output_data
        output_data = []  # Reset the output data each time

        try:
            request, socket = self.request

            if settings.Config.AnalyzeMode:
                ParseDatagramNBTNames(request, self.client_address[0])
                BecomeBackup(request, self.client_address[0])

            BecomeBackup(request, self.client_address[0])

        except Exception as e:
            output_data.append(f"Error in Browser.handle: {e}")

        return output_data