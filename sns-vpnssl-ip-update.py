import os, sys, re
import credentials
from datetime import datetime
from paramiko import SSHClient, AutoAddPolicy
from scp import SCPClient

parent_dir = os.path.dirname(os.path.realpath(__file__)

def log(message, error):
    open('{path}/sns-vpnssl-ip-update.log'.format(path=parent_dir)), 'a').write(message + '\n')
    if error == 0: print(message)
    else: sys.exit(message)

def getIPv4():
    ipv4 = os.popen("curl -s 'https://ip4.seeip.org'").read()
    if not ipv4: return False
    else: return ipv4

class Firewall:

    def __init__(self):

        # Vérifie le format du nom d'hôte (FQDN ou adresse IP)
        regex_hostname = '^(\w*\.)*\w*[^\.]$'
        regex_ip_address = '^((\d){1,3}\.){3}(\d){1,3}$'
        if re.match(regex_hostname, hostname): self.hostname = creds['hostname']
        elif re.match(regex_ip_address, hostname):
            for byte in hostname.split('.'):
                if int(byte) < 0 or int(byte) > 255:
                    log('[-] ERROR: Invalid IP address ({ip_address})'.format(ip_address=creds['hostname']), 1)
            self.hostname = credentials.hostname
        else: log('[-] ERROR: Invalid hostname (must be IP or FQDN)', 1)
    
        # Vérifie le format du port (compris dans la plage 0-65535)
        try: int(port)
        except: log('[-] ERROR: Invalid port (must be in range 0-65535)', 1)
        if int(port) > 0 or int(port) < 65535: self.port = credentials.port
        else: log('[-] ERROR: Invalid port (must be in range 0-65535)', 1)

        # Vérifie le format des identifiants
        if '' in (username, password):
            log('[-] ERROR: No credentials were provided to connect to {hostname}'.format(hostname=hostname), 1)
        else:
            self.username = credentials.username
            self.password = credentials.password
    
    def execute(self, command):
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        try: ssh.connect(self.hostname, self.port, self.username, self.password)
        except: log('[-] ERROR: Unable to connect to {hostname}'.format(hostname=self.hostname), 1)

        stdin, stdout, stderr = ssh.exec_command(command)
        lines = stdout.readlines()
        return lines

    def downloadConfig(self):
        log('[+] Downloading OpenVPN configuration from {hostname}'.format(hostname=self.hostname), 0)
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        try: ssh.connect(self.hostname, self.port, self.username, self.password)
        except: log('[-] ERROR: Unable to connect to {hostname}'.format(hostname=self.hostname), 1)

        with SCPClient(ssh.get_transport()) as scp:
            try: scp.get('~/ConfigFiles/Openvpn/openvpn', local_path=parent_dir)
            except: log('[-] ERROR: Unable to pull OpenVPN configuration file', 1)
    
        log('[+] Configuration downloaded', 0)

    def updateConfig(self, openvpn_ip, public_ip):
        log('[+] Updating configuration', 0)
        os.popen("sed -i '' -e 's/serverPublicAddr={openvpn_ip}/serverPublicAddr={public_ip}/g' openvpn".format(
            openvpn_ip=openvpn_ip,
            public_ip=public_ip))
        log('[+] OpenVPN configuration was updated with the new public IP address ({public_ip})'.format(public_ip=public_ip), 0)

    def uploadConfig(self):
        log('[+] Uploading configuration to {hostname}'.format(hostname=self.hostname), 0)
        ssh = SSHClient()
        ssh.set_missing_host_key_policy(AutoAddPolicy())

        try: ssh.connect(self.hostname, self.port, self.username, self.password)
        except: log('[-] ERROR: Unable to connect to {hostname}'.format(hostname=self.hostname), 1)

        with SCPClient(ssh.get_transport()) as scp:
            try: scp.put('{path}/openvpn'.format(path=parent_dir), remote_path='~/ConfigFiles/Openvpn')
            except: log('[-] ERROR: Unable to push OpenVPN configuration file', 1)
        
        log('[+] OpenVPN configuration was updated', 0)
        self.reloadConfig()

    def reloadConfig(self):
        log('[+] Restarting OpenVPN service on {hostname}'.format(hostname=hostname), 0)
        try: self.execute('enopenvpn')
        except: log('[-] ERROR: Unable to restart OpenVPN', 1)

# Horodatage de l'opération
timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
log('{timestamp} :'.format(timestamp=timestamp), 0)

firewall = Firewall()

# Téléchargement de la configuration OpenVPN
firewall.downloadConfig()

# Vérification de l'adresse IP publique portée par le pare-feu
log('[+] Checking public IP address', 0)
public_ip = getIPv4()
if public_ip == False:
    log('[-] ERROR: Unable to reach IPv4 API', 1)
else: 
    log('[+] Public IP address is {public_ip}'.format(public_ip=public_ip), 0)

# Vérification de l'adresse IP utilisée par OpenVPN
openvpn_ip = None
pattern = re.compile('^serverPublicAddr=((\d){1,3}\.){3}(\d){1,3}$')
for i, line in enumerate(open('./openvpn')):
    for match in re.finditer(pattern, line):
        openvpn_ip = match.group().split('=')[1]
log('[+] OpenVPN uses the IP address {openvpn_ip}'.format(openvpn_ip=openvpn_ip), 0)

# Mise à jour de la configuration OpenVPN
if public_ip != openvpn_ip:
    firewall.updateConfig()
    firewall.uploadConfig()
else: log('[+] OpenVPN configuration is up to date', 0)