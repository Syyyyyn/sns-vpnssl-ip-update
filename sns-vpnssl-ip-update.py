import os
import sys
import re
from datetime import datetime
import paramiko

def log(message, error):
    open('./sns-vpnssl-ip-update.log', 'a').write(message + '\n')
    if error == 0: print(message)
    else: sys.exit(message)

def getIPv4():
    ipv4 = os.popen("curl -s 'https://ip4.seeip.org'").read()
    if not ipv4: return False
    else: return ipv4

def downloadConfig(host, username, password):
    try: os.popen('sshpass -p "{password}" scp {username}@{host}:ConfigFiles/Openvpn/openvpn .'.format(password=password, username=username, host=host))
    except: log('[-] ERROR: Unable to reach {host}'.format(host=host), 1)

def uploadConfig(host, username, password):
    try: os.popen('sshpass -p "{password}" scp ./openvpn {username}@{host}:ConfigFiles/Openvpn/openvpn'.format(password=password, username=username, host=host))
    except: log('[-] ERROR: Unable to reach {host}'.format(host=host), 1)

def updateConfig(openvpn_ip, public_ip):
    os.popen("sed -i '' -e 's/serverPublicAddr={openvpn_ip}/serverPublicAddr={public_ip}/g' openvpn".format(openvpn_ip=openvpn_ip, public_ip=public_ip))

class Host:
    def __init__(self, hostname, credentials, port = 22):
        self.port = port
        self.username = credentials[0]
        self.password = credentials[1]

        # Verify hostname format (ip_address or plain text hostname)
        regex_ip = '^((\d){1,3}\.){3}(\d){1,3}$'
        regex_fqdn = '^(\w*\.)*\w*[^\.]$'

        if re.match(regex_fqdn, hostname): self.hostname = hostname
        elif re.match(regex_ip, hostname):
            for byte in hostname.split('.'):
                if int(byte) < 0 or int(byte) > 255: sys.exit('ERROR:INVALID_IP_ADDRESS')
            self.hostname = hostname
        else: sys.exit('ERROR:INVALID_HOSTNAME')
    
        # Verify port format (in range 0-65535)
        try: int(port)
        except: sys.exit('ERROR:INVALID_PORT_VALUE')
        if int(port) < 0 or int(port) > 65535: sys.exit('ERROR:INVALID_PORT_RANGE')
        
    
    def getInfo(self):
        print('host:', self.hostname)
        if self.port == 22: print('port:', self.port, '(default)')
        else: print('port:', self.port)
        print('username:', self.username)
        print('password:', self.password)
    
    def execute(self, command):
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try: ssh.connect(self.hostname, self.port, self.username, self.password)
        except: sys.exit('ERROR:WRONG_CREDENTIALS')

        stdin, stdout, stderr = ssh.exec_command(command)
        lines = stdout.readlines()
        return lines

# Informations de connexion au pare-feu
host = ''
username = ''
password = ''

# Horodatage de l'opération
timestamp = datetime.now().strftime('%d-%m-%Y %H:%M:%S')
log('{timestamp} :'.format(timestamp=timestamp), 0)

# Téléchargement de la configuration OpenVPN
log('[+] Downloading OpenVPN configuration from {host}'.format(host=host), 0)
downloadConfig(host, username, password)
if not os.path.isfile('./openvpn'): log('[-] ERROR: Unable to retrieve OpenVPN configuration file', 1)
log('[+] Configuration downloaded', 0)

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
    for match in re.finditer(pattern, line): openvpn_ip = match.group().split('=')[1]
log('[+] OpenVPN uses the IP address {openvpn_ip}'.format(openvpn_ip=openvpn_ip), 0)

if public_ip != openvpn_ip:
    # Mise à jour de la configuration OpenVPN
    log('[+] Updating configuration', 0)
    updateConfig(openvpn_ip, public_ip)
    log('[+] OpenVPN configuration was updated with the new public IP address ({public_ip})'.format(public_ip=public_ip), 0)
    log('[+] Uploading configuration to {host}'.format(host=host), 0)
    uploadConfig(host, username, password)
    log('[+] OpenVPN configuration was updated', 0)

    # Redémarrage du service OpenVPN
    log('[+] Restarting OpenVPN service on {host}'.format(host=host), 0)
    try: Host(host, (username, password), 22).execute('enopenvpn')
    except: log('[-] ERROR: Unable to restart OpenVPN', 1)

else: log('[+] OpenVPN configuration is up to date', 0)