import sys
import os
import datetime
import struct
import socket

sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), '..')))
from packets import SMB2Header, SMB2Nego, SMB2NegoData

def GetBootTime(data):
    Filetime = int(struct.unpack('<q',data)[0])
    t = divmod(Filetime - 116444736000000000, 10000000)
    time = datetime.datetime.fromtimestamp(t[0])
    return time, time.strftime('%Y-%m-%d %H:%M:%S')


def IsDCVuln(t):
    Date = datetime.datetime(2014, 11, 17, 0, 30)
    if t[0] < Date:
       print ("DC is up since:", t[1])
       print ("This DC is vulnerable to MS14-068")
    print ("DC is up since:", t[1])


def run(host):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(host)  
    s.settimeout(5) 

    Header = SMB2Header(Cmd="\x72",Flag1="\x18",Flag2="\x53\xc8")
    Nego = SMB2Nego(Data = SMB2NegoData())
    Nego.calculate()

    Packet = str(Header)+str(Nego)
    Buffer = struct.pack(">i", len(Packet)) + Packet
    s.send(Buffer)

    try:
        data = s.recv(1024)
        if data[4:5] == "\xff":
           print ("This host doesn't support SMBv2") 
        if data[4:5] == "\xfe":
           IsDCVuln(GetBootTime(data[116:124]))
    except Exception:
        s.close()
        raise

if __name__ == "__main__":
    if len(sys.argv)<=1:
        sys.exit('Usage: python '+sys.argv[0]+' DC-IP-address')
    host = sys.argv[1],445
    run(host)
