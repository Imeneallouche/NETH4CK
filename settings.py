import utils
import configparser
import binascii
from utils import *

__version__ = 'Responder 2.3'

class Settings:
	
	def __init__(self):
		self.ResponderPATH = os.path.dirname(__file__)
		self.Bind_To = '0.0.0.0'

	def __str__(self):
		ret = 'Settings class:\n'
		for attr in dir(self):
			value = str(getattr(self, attr)).strip()
			ret += "    Settings.%s = %s\n" % (attr, value)
		return ret

	def toBool(self, str):
		return str.upper() == 'ON'

	def ExpandIPRanges(self):
		def expand_ranges(lst):
			ret = []
			for l in lst:
				tab = l.split('.')
				x = {}
				i = 0
				for byte in tab:
					if '-' not in byte:
						x[i] = x[i+1] = int(byte)
					else:
						b = byte.split('-')
						x[i] = int(b[0])
						x[i+1] = int(b[1])
					i += 2
				for a in range(x[0], x[1]+1):
					for b in range(x[2], x[3]+1):
						for c in range(x[4], x[5]+1):
							for d in range(x[6], x[7]+1):
								ret.append('%d.%d.%d.%d' % (a, b, c, d))
			return ret

		self.RespondTo = expand_ranges(self.RespondTo)
		self.DontRespondTo = expand_ranges(self.DontRespondTo)

	def populate(self, options):

		if options.Interface is None and utils.IsOsX() is False:
			print(utils.color("Error: -I <if> mandatory option is missing", 1))
			sys.exit(-1)

		# Config parsing
		config = configparser.ConfigParser()
		config.read(os.path.join(self.ResponderPATH, 'Responder.conf'))

		# Servers
		self.HTTP_On_Off     = self.toBool(config.get('Responder Core', 'HTTP'))
		self.SSL_On_Off      = self.toBool(config.get('Responder Core', 'HTTPS'))
		self.SMB_On_Off      = self.toBool(config.get('Responder Core', 'SMB'))
		self.SQL_On_Off      = self.toBool(config.get('Responder Core', 'SQL'))
		self.FTP_On_Off      = self.toBool(config.get('Responder Core', 'FTP'))
		self.POP_On_Off      = self.toBool(config.get('Responder Core', 'POP'))
		self.IMAP_On_Off     = self.toBool(config.get('Responder Core', 'IMAP'))
		self.SMTP_On_Off     = self.toBool(config.get('Responder Core', 'SMTP'))
		self.LDAP_On_Off     = self.toBool(config.get('Responder Core', 'LDAP'))
		self.DNS_On_Off      = self.toBool(config.get('Responder Core', 'DNS'))
		self.Krb_On_Off      = self.toBool(config.get('Responder Core', 'Kerberos'))

		# Db File
		self.DatabaseFile    = os.path.join(self.ResponderPATH, config.get('Responder Core', 'Database'))

		# Log Files
		self.LogDir = os.path.join(self.ResponderPATH, 'logs')

		if not os.path.exists(self.LogDir):
			os.mkdir(self.LogDir)

		self.SessionLogFile      = os.path.join(self.LogDir, config.get('Responder Core', 'SessionLog'))
		self.PoisonersLogFile    = os.path.join(self.LogDir, config.get('Responder Core', 'PoisonersLog'))
		self.AnalyzeLogFile      = os.path.join(self.LogDir, config.get('Responder Core', 'AnalyzeLog'))

		self.FTPLog          = os.path.join(self.LogDir, 'FTP-Clear-Text-Password-%s.txt')
		self.IMAPLog         = os.path.join(self.LogDir, 'IMAP-Clear-Text-Password-%s.txt')
		self.POP3Log         = os.path.join(self.LogDir, 'POP3-Clear-Text-Password-%s.txt')
		self.HTTPBasicLog    = os.path.join(self.LogDir, 'HTTP-Clear-Text-Password-%s.txt')
		self.LDAPClearLog    = os.path.join(self.LogDir, 'LDAP-Clear-Text-Password-%s.txt')
		self.SMBClearLog     = os.path.join(self.LogDir, 'SMB-Clear-Text-Password-%s.txt')
		self.SMTPClearLog    = os.path.join(self.LogDir, 'SMTP-Clear-Text-Password-%s.txt')
		self.MSSQLClearLog   = os.path.join(self.LogDir, 'MSSQL-Clear-Text-Password-%s.txt')

		self.LDAPNTLMv1Log   = os.path.join(self.LogDir, 'LDAP-NTLMv1-Client-%s.txt')
		self.HTTPNTLMv1Log   = os.path.join(self.LogDir, 'HTTP-NTLMv1-Client-%s.txt')
		self.HTTPNTLMv2Log   = os.path.join(self.LogDir, 'HTTP-NTLMv2-Client-%s.txt')
		self.KerberosLog     = os.path.join(self.LogDir, 'MSKerberos-Client-%s.txt')
		self.MSSQLNTLMv1Log  = os.path.join(self.LogDir, 'MSSQL-NTLMv1-Client-%s.txt')
		self.MSSQLNTLMv2Log  = os.path.join(self.LogDir, 'MSSQL-NTLMv2-Client-%s.txt')
		self.SMBNTLMv1Log    = os.path.join(self.LogDir, 'SMB-NTLMv1-Client-%s.txt')
		self.SMBNTLMv2Log    = os.path.join(self.LogDir, 'SMB-NTLMv2-Client-%s.txt')
		self.SMBNTLMSSPv1Log = os.path.join(self.LogDir, 'SMB-NTLMSSPv1-Client-%s.txt')
		self.SMBNTLMSSPv2Log = os.path.join(self.LogDir, 'SMB-NTLMSSPv2-Client-%s.txt')

		# HTTP Options
		self.Serve_Exe	      = self.toBool(config.get('HTTP Server', 'Serve-Exe'))
		self.Serve_Always     = self.toBool(config.get('HTTP Server', 'Serve-Always'))
		self.Serve_Html       = self.toBool(config.get('HTTP Server', 'Serve-Html'))
		self.Html_Filename    = config.get('HTTP Server', 'HtmlFilename')
		self.Exe_Filename     = config.get('HTTP Server', 'ExeFilename')
		self.Exe_DlName       = config.get('HTTP Server', 'ExeDownloadName')
		self.WPAD_Script      = config.get('HTTP Server', 'WPADScript')
		self.HtmlToInject     = config.get('HTTP Server', 'HtmlToInject')

		if not os.path.exists(self.Html_Filename):
			print(utils.color("/!\ Warning: %s: file not found" % self.Html_Filename, 3, 1))

		if not os.path.exists(self.Exe_Filename):
			print(utils.color("/!\ Warning: %s: file not found" % self.Exe_Filename, 3, 1))

		# SSL Options
		self.SSLKey  = config.get('HTTPS Server', 'SSLKey')
		self.SSLCert = config.get('HTTPS Server', 'SSLCert')

		# Respond to hosts
		self.RespondTo         = filter(None, [x.upper().strip() for x in config.get('Responder Core', 'RespondTo').strip().split(',')])
		self.RespondToName     = filter(None, [x.upper().strip() for x in config.get('Responder Core', 'RespondToName').strip().split(',')])
		self.DontRespondTo     = filter(None, [x.upper().strip() for x in config.get('Responder Core', 'DontRespondTo').strip().split(',')])
		self.DontRespondToName = filter(None, [x.upper().strip() for x in config.get('Responder Core', 'DontRespondToName').strip().split(',')])

		# Auto Ignore List
		self.AutoIgnore                 = self.toBool(config.get('Responder Core', 'AutoIgnoreAfterSuccess'))
		self.CaptureMultipleCredentials = self.toBool(config.get('Responder Core', 'CaptureMultipleCredentials'))
		self.AutoIgnoreList             = []

		# CLI options
		self.LM_On_Off       = options.LM_On_Off
		self.WPAD_On_Off     = options.WPAD_On_Off
		self.Wredirect       = options.Wredirect
		self.NBTNSDomain     = options.NBTNSDomain
		self.Basic           = options.Basic
		self.Finger_On_Off   = options.Finger
		self.Interface       = options.Interface
		self.OURIP           = options.OURIP
		self.Force_WPAD_Auth = options.Force_WPAD_Auth
		self.Upstream_Proxy  = options.Upstream_Proxy
		self.AnalyzeMode     = options.Analyze
		self.Verbose         = options.Verbose
		self.CommandLine     = str(sys.argv)

		if self.HtmlToInject is None:
			self.HtmlToInject = ''

		self.Bind_To = utils.FindLocalIP(self.Interface, self.OURIP)

		self.IP_aton         = socket.inet_aton(self.Bind_To)
		self.Os_version      = sys.platform

		# Set up Challenge
		self.NumChal = config.get('Responder Core', 'Challenge')

		if len(self.NumChal)!=16:
			print(utils.color("[!] The challenge must be exactly 16 chars long.\nExample: 1122334455667788", 1))
			sys.exit(-1)

		self.Challenge = ""
		for i in range(0, len(self.NumChal), 2):
			self.Challenge += binascii.unhexlify(self.NumChal[i:i+2])

		# Set up logging
		logging.basicConfig(filename=self.SessionLogFile, level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
		logging.warning('Responder Started: %s' % self.CommandLine)
		logging.warning('Responder Config: %s' % str(self))

		Formatter = logging.Formatter('%(asctime)s - %(message)s')
		PLog_Handler = logging.FileHandler(self.PoisonersLogFile, 'w')
		ALog_Handler = logging.FileHandler(self.AnalyzeLogFile, 'a')
		PLog_Handler.setLevel(logging.INFO)
		ALog_Handler.setLevel(logging.INFO)
		PLog_Handler.setFormatter(Formatter)
		ALog_Handler.setFormatter(Formatter)

		self.PoisonersLogger = logging.getLogger('Poisoners Log')
		self.PoisonersLogger.addHandler(PLog_Handler)

		self.AnalyzeLogger = logging.getLogger('Analyze Log')
		self.AnalyzeLogger.addHandler(ALog_Handler)

def init():
	global Config
	Config = Settings()
