import socket
import struct

from utils import color
from packets import SMBHeader, SMBNego, SMBNegoFingerData, SMBSessionFingerData

def OsNameClientVersion(data):
	try:
		length = struct.unpack('<H',data[43:45])[0]
		pack = tuple(data[47+length:].split('\x00\x00\x00'))[:2]
		OsVersion, ClientVersion = tuple([e.replace('\x00','') for e in data[47+length:].split('\x00\x00\x00')[:2]])
		return OsVersion, ClientVersion
	except:
	 	return "Could not fingerprint Os version.", "Could not fingerprint LanManager Client version"

def RunSmbFinger(host):
	try:
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.connect(host)
		s.settimeout(0.7)

		h = SMBHeader(cmd="\x72",flag1="\x18",flag2="\x53\xc8")
		n = SMBNego(data = SMBNegoFingerData())
		n.calculate()
		
		Packet = str(h)+str(n)
		Buffer = struct.pack(">i", len(''.join(Packet)))+Packet
		s.send(Buffer)
		data = s.recv(2048)
		
		if data[8:10] == "\x72\x00":
			Header = SMBHeader(cmd="\x73",flag1="\x18",flag2="\x17\xc8",uid="\x00\x00")
			Body = SMBSessionFingerData()
			Body.calculate()

			Packet = str(Header)+str(Body)
			Buffer = struct.pack(">i", len(''.join(Packet)))+Packet  

			s.send(Buffer) 
			data = s.recv(2048)

		if data[8:10] == "\x73\x16":
			return OsNameClientVersion(data)
	except:
		print color("[!] ", 1, 1) +" Fingerprint failed"
		return None
