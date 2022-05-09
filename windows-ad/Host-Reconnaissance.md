#### Seatbelt - Gather generic info of the host
- https://github.com/GhostPack/Seatbelt
```
Seatbelt.exe -group=system
Seatbelt.exe -group=user
Seatbelt.exe -group=all
```

#### Get loggged on sessions
```
net logons
```

#### Get list of running processes
```
ps
```

#### Check if RSAT tools is installed
```
Get-Module -List -Name GroupPolicy | select -expand ExportedCommands
```

#### Install RSAT Tools
```
Install-WindowsFeature –Name GPMC
```

#### Get all GPO's applied to a machine
- Run with elevated prompt
```
gpresult /H gpos.html
```
