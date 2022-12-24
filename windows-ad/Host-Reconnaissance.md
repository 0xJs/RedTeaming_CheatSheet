# Host-Reconnaissance.md
* [Automated](#Automated)
* [Manual enumeration](#Manual-enumeration)
* [Misc](#Misc)

## Automated
#### Seatbelt - Gather generic info of the host
- https://github.com/GhostPack/Seatbelt
```
Seatbelt.exe -group=system
Seatbelt.exe -group=user
Seatbelt.exe -group=all
```

## Manual enumeration
### General
#### Get hostname
```
hostname
```

#### Get system info
```
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

### Users
#### Local users
```
net users
```

#### Get loggged on sessions
```
query user
```

### Networking
#### Current configuration
```
ipconfig
```

#### Routes
```
route print
```

#### Arp table
```
arp -A
```

#### Open ports
```
netstat -ano
```

#### Firewall
```
netsh firewall show state
netsh firewall show config
```


### Task and processes
#### Get list of running processes
```
ps
```

#### list tasks
```
schtasks /query /fo LIST /v
tasklist /SVC
```

### GPO
#### Get all GPO's applied to a machine
- Run with elevated prompt
```
gpresult /H gpos.html
```

### Misc
#### Check if RSAT tools is installed
```
Get-Module -List -Name GroupPolicy | select -expand ExportedCommands
```

#### Install RSAT Tools
```
Install-WindowsFeature –Name GPMC
```


