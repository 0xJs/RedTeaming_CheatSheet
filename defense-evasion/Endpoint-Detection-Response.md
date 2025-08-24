## Endpoint Detection Response
- [Enumerate EDR's](#enumerate-edrs)
- [EDR Internals](#edr-internals)
  - [Kernel Callbacks](#kernel-callbacks)
    - [Enumerate Kernel Callbacks](#enumerate-kernel-callbacks)
    - [Removing kernel callbacks](#removing-kernel-callbacks)
  - [Event Tracing for Windows (ETW)](#event-tracing-for-windows-etw)
    - [User-mode Enumeration](#user-mode-enumeration)
    - [Kernel-mode enumeration](#kernel-mode-enumeration)
    - [Disabling ETW providers User-Mode](#disabling-etw-providers-user-mode)
    - [Disable ETW providers Kernel-Mode](#disable-etw-providers-kernel-mode)
  - [Minifilters](#minifilters)
    - [Manual Altitude takeover](#manual-altitude-takeover)
    - [Automated Tools](#automated-tools)
  - [Network Telemetry](#network-telemetry)
    - [Blocking EDR's traffic](#blocking-edrs-traffic)
  - [Other attacks](#other-attacks)
    - [Token Downgrade](#token-downgrade)

## Enumerate EDR's
- Enumerates EDR's running on the system by enumerating current processes and loaded drivers.
- https://github.com/0xJs/EnumEDR-s

```
.\EnumEDR.exe --edr
```

## EDR Internals
- Kernel Callbacks - Kernel callbacks are functions registered with the operating system kernel that are automatically executed when specific system events occur. Drivers often utilize them to monitor system activity and respond to these events. The following kernel callbacks exists:
	- Process Creation Kernel Callbacks
		- Notifies process creation or termination from API calls such as `NtCreateUserProcess` or `NtCreateProcessEx` to monitor for and register (malicious) process creation and which image (PE file) created the process. These calls end up in kernel mode at `PspCallProcessNotifyRoutines`
		- Drivers register callback routines using `PsSetCreateProcessNotifyRoutine`, `PsSetCreateProcessNotifyRoutineEx` and `PsSetCreateProcessNotifyRoutineEx2` stored in array of `PspCallProcessNotifyRoutine`
		- Collects telemetry from such as;
			- [EPROCESS](https://www.vergiliusproject.com/kernels/x64/windows-11/21h2/_EPROCESS) structure of the created process
			- PID of the created process
			- [PPS_CREATE_NOTIFY_INFO](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_ps_create_notify_info) structure which contains `ParentProcessId`, `ImageFileName`, `CommandLine` and `CreatingThreadId`
	- Thread Creation Kernel Callbacks
		- Notifies thread creation or termination from API calls such as `NtCreateThreadEx`, `NtTerminateThread` to monitor for malicious thread creation (Process injection etc.). These calls end up in kernel mode at `PspCallThreadNotifyRoutines`
		- Drivers register callback routines using `PsSetCreateThreadNotifyRoutine` and `PsSetCreateThreadNotifyRoutineEx` stored in array of `PspCreateThreadNotifyRoutine`
		- Collects telemetry such as;
			- [ETHREAD](https://www.vergiliusproject.com/kernels/x64/windows-11/22h2/_ETHREAD) structure of the created thread
			- PID of the process that created the thread
			- TID of the created thread
	- Image Load Kernel Callbacks
		- Notifies loading PE images such as `.sys` drivers, `.dlls` or `.exe` from API calls such as `NtMapViewOfSection`, `LdrLoadDll` to monitor for malicious image loading.  These calls end up in the kernel mode at `PsCallImageNoutifyRoutines`
		- Driver registers callback routines using `PsSetLoadImageNotifyRoutine` and `PsSetLoadImageNotifyRoutineEx` stored in array of `PspLoadImageNotifyRoutine`
		- Collects telemetry such as;
			- Full Image name of the loaded image
			- PID of the process which loads the image
			- Base address of the loaded image
			- Size of the image
	- Registry Operation Kernel Callbacks
		- Notifies operations such as reading, writing, deleting or querying the Windows Registry entries from API calls such as `NtOpenKeyEx`, `NtSetValueKey` to monitor for malicious registry operations used for malicious activity such as persistence or privilege escalation.  These calls end up in kernel mode at `CmpCallCallBacks` and `CmpCallCallBacksEx`
		- Driver registers callbacks routines using `cmRegisterCallback` and `cmRegisterCallbackEx` stored within double linked list headed by `CallbackListHead`
		- Collects telemetry such as;
			- Full name of the registry key
			- PID of the process that performs the operation
			- TID of the thread that performs the operation
	- Process/Thread Object Pre/Post Operation Kernel Callbacks
		- Notifies requests for handles to objects from API calls such as `NtOpenProcess` to monitor for malicious object operations such as LSASS memory dumping or remote code injection. These calls end up in kernel mode with `ObpCallPreOperationCallbacks`
		- Drivers registers callback routines using `ObRegisterCallbacks` stored within a double linked list headed by `PsProcessType->CallbackList` and `PsThreadType->CallbackList`
		- Collects telemetry such as;
			- Target & source PID
			- Desired access
			- TID of the thread initiating the handle creation/duplication
	- Filesystem Operation Kernel Callbacks (Minifilter)
		- Minifilter Kernel Callbacks notifies for filesystem operations such as creation, writing and closing of files to monitor for malicious filesystem operations like dropping malware on disk or encrypting a large number of files. These calls end up in kernel mode at minifilters registered pre- and post-operation callback routines, such as `PreCreate`, `PreWrite`, and `PostCleanup`
		- Drivers registers callbacks using `PreOperationCallback` and `PostOperationCallback` during minifilter registration with `FltRegisterFilter` and are stored within a `CALLBACK_NODE` structure within filter instances
		- Collects telemetry such as;
			- Type of filesystem operation
			- PID of the process & TID of the thread
			- Path & Size of the file operation
- Event Tracing for Windows Telemetry
	- ETW is a general-purpose, high speed tracing facility provided by the operating system. Using a buffering and logging mechanism implemented in the kernel, ETW provides a tracing mechanism for events raised by user-mode applications and kernel-mode device drivers.
	- ETW generates telemetry based on providers. The EDR has a consumer to create sessions to monitor for these events. 
	- Collects telemetry from a wide range of events such as events from the common language runtime, which is loaded into every .NET process, emits unique events using ETW. 
	- Microsoft Windows Threat Intelligence (EtwTi) is a special ETW provider
		- It is some of the most powerful detection source on Windows.
		- Collects telemetry such as; 
			- Memory allocations
			- Driver loads
			- Syscall policy violations to win32k
- Network telemetry
	- Windows Filtering Platform
		- Used to perform filtering and monitoring of operations on network data and collect telemetry by implementing callouts and extracting metadata
		- Collects telemetry such as;
			- Basic network information
			- The `ProcessPath`, `ProccessId` and `token` members.
- Hooked API Telemetry
	- Used to hook NTAPI functions in `ntdll.dll` by redirecting execution (via a jump instruction) to a custom or malicious implementation. With API hooking, any form of telemetry collection or behavior modification is possible.
- Others
	- AI/ML-Based Detection help identify anomaly behavior
	- Cloud Submission/Scanning uploaded to cloud based threat intel systems
	- YARA Rules & Signature Scanning of known malware of known patterns and memory
	- Threat Hunting Automation scan for TTP's of compromise
	- Sandboxing to observe behavior
	- Threat Hunting Automation
	- Deception Technology such as honey tokens and files
	- Exploit Mitigation stack integrity checks and memory protections
	- Memory scanning

![](Pasted%20image%2020250505121406.png)

- A small implementation of such kernel callbacks are implemented in [MyMiniEDR](https://github.com/0xJs/MyMiniEDR) project. Which I might develop further.

## Kernel Callbacks
### Reverse kernel callbacks registrations of EDR driver
- Open the EDR driver in IDA.
	- Check the IAT for the functions that register a specific kernel callback `PsSetXXXXXNotifyRoutine`.
	- Check if they are dynamically resolved by searching trough `mmGetSystemRoutineAddress`
	- Then click on it and press `x`  to cross reference, check where they are called and what they are doing
- List of kernel callback functions
	- Process creation – [`PsSetCreateProcessNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine), [`PsSetCreateProcessNotifyRoutineEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutineex), [`PsSetCreateProcessNotifyRoutineEx2`](https://learn.microsoft.com/en-us/windows-hardware/drivers/wdf/nf-wdf-ntddk-pssetcreateprocessnotifyroutineex2)
	- Thread creation – [`PsSetCreateThreadNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutine), [`PsSetCreateThreadNotifyRoutineEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreatethreadnotifyroutineex)
	- Image load – [`PsSetLoadImageNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutine), [`PsSetLoadImageNotifyRoutineEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetloadimagenotifyroutineex)
	- Registry operations – [`CmRegisterCallback`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallback), [`CmRegisterCallbackEx`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-cmregistercallbackex)
	- Object operations – [`ObRegisterCallbacks`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-obregistercallbacks)
	- Minifilter operations – [`FltRegisterFilter`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltregisterfilter)

### Enumerate Kernel Callbacks
#### DCMB
- Project to check for Kernel Callbacks; https://github.com/GetRektBoy724/DCMB

#### Windbg
- [WinDbg – Removing Kernel Callbacks](Windbg.md#removing-kernel-callbacks)

#### Vulnerable driver
- [Driver Attacks – Kernel Callback Remover](Driver-Attacks.md#kernel-callback-remover)

### Removing kernel callbacks
#### Windbg
- [WinDbg – Removing Kernel Callbacks](Windbg.md#removing-kernel-callbacks)

#### Vulnerable driver
- [Driver Attacks – Kernel Callback Remover](Driver-Attacks.md#kernel-callback-remover)

## Event Tracing for Windows (ETW)
### Reverse ETW registrations of EDR driver
- Open the EDR driver in IDA.
	- Check the IAT for the functions that registers ETW `EtwRegister`
	- Check if they are dynamically resolved by searching trough `mmGetSystemRoutineAddress`
	- Then click on it and press `x`  to cross reference, check where they are called and what they are doing

### User-mode Enumeration
#### List number of built-in ETW providers
```
logman.exe query providers | find /c /v ""
```

#### List all built-in ETW Providers & GUID
```
logman.exe query providers
```

#### List ETW provider events
```
logman.exe query providers <PROVIDER NAME>
```

#### List active tracing sessions
- EDR's sessions are protected from user-mode access such as `DefenderAuditLogger` & `DefenderApiLogger`

```
logman.exe query -ets
```

#### List sessions providers
```
logman.exe query <TRACING SESSION NAME> -ets
```

### Kernel-mode enumeration
#### Windbg
- Enumerates ETW providers and consumers in kernel mode.
- https://github.com/trailofbits/WinDbg-JS

```
dx @$cursession.Processes.Select(p => @$scriptContents.EtwConsumersForProcess(p))
```

- Resolve GUID

```
logman.exe query proviers {<GUID>}
```

### Disabling ETW providers User-Mode
#### Disable normal ETW providers
- Normal ETW providers can be disabled from user-mode. Secure providers from EDR's can't be disabled or queried without service or process running protected as `PROTECTION_LEVEL_ANTIMALWARE_LIGHT`
- Even as `nt authority\system` disabling secure providers does not work

```
logman.exe update trace <TRACING SESSION NAME> --p <PROVIDER NAME> -ets 
```

#### Bypass ETW User-Mode providers
- Win32 API:
	  - [`GetProcAddress`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress) & [`GetModuleHandle`](https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulehandlew) - To get address of `EtwEventWrite` function
	  - [`NtProtectVirtualMemory`](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtProtectVirtualMemory.html) - To change the memory protections to `PAGE_READWRITE`
	  - [`NtWriteVirtualMemory`](http://undocumented.ntinternals.net/index.html?page=UserMode%2FUndocumented%20Functions%2FMemory%20Management%2FVirtual%20Memory%2FNtWriteVirtualMemory.html) - To write the `0x48 0x33 0xc0 0xc3` patch to `EtwEventWrite` function
	  - [`NtProtectVirtualMemory`](NtProtectVirtualMemory) - Restore memory protections
- Overwrites `EtwEventWrite` with `0x48 0x33 0xc0 0xc3`
- Better bypass would be https://www.praetorian.com/blog/etw-threat-intelligence-and-hardware-breakpoints/

### Disable ETW providers Kernel-Mode
#### Windbg
- [WinDbg – ETW Kernel-mode provider](Windbg.md#etw-kernel-mode-provider)

#### Disable Microsoft Windows Threat Intelligence (EtwTi)
- [Driver Attacks – ETwTi Remover](Driver-Attacks.md#etwti-remover)

## Minifilters
#### Load order explained
- Minifilters with the highest altitude process the I/O Pre Operation requests first and Minifilters in lower Load Order Groups are loaded first. [MS Docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/load-order-groups-and-altitudes-for-minifilter-drivers#types-of-load-order-groups-and-their-altitude-ranges).
- The following registry keys are relevant:
	- The `Group` `REG_SZ` key under `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<SERVICE>` determines the Load Order group
	- The `Start` `REG_DWORD` key under `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<SERVICE>` determines how a service is started
		- All drivers that specify a start type of `SERVICE_BOOT_START` are loaded before drivers with a start type of `SERVICE_SYSTEM_START` or `SERVICE_AUTO_START`. Within each start type category, the load order group determines when file system filter drivers (and legacy filter drivers) will be loaded. [MS Docs](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/what-determines-when-a-driver-is-loaded#driver-start-types)
	- The `Altitude` `REG_SZ` key under `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\<SERVICE>\Instances\<INSTANCENAME>` determines the altitude integer value.
- There are many default unused filters under `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\` like `WIMMOUNT`, `npsvctrig`. These can be used to take over the altitude of a security one

### Manual Altitude takeover
#### List all the loaded minifilters and their altitude
- Known minifilters
	- `MsSecFlt` is for MDE
	- `WdFilter` is Defender
- If the minifilter has a altitude of `xxxxx.yyyyy` it **can not** be taken over as the `yyyyy` is dynamically assigned and changes every time it is loaded.

```
fltmc
```

#### Identify already signed filter
- Open registry Editor and go to `Computer\HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\` and find a service with a subkey `Instances`
	- For example `npsvctrig`
- Or loop through them with PowerShell

```powershell
Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Services" | Where-Object {Test-Path "$($_.PSPath)\Instances"} | Select-Object PSChildName
```

#### Change Altitude value through registry
- Change/add the `Altitude` `REG_SZ` key under to a security minifilter one
- Change/add the `Start` `REG_DWORD` value to 0
- Change/add the `Group` `REG_SZ` value to for example `FSFilter Bottom` or lower (`40000-49999`)
- Then reboot the system

```
Set Altitude to a security minifilter range
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE>\Instances\<INSTANCENAME>" /v Altitude /t REG_SZ /d "<ALTITUDE OF SECURITY MINI FILTER>" /f

Set Start to 0 (BOOT_START)
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE>" /v Start /t REG_DWORD /d 0 /f

Set Group to "FSFilter Bottom"
reg add "HKLM\SYSTEM\CurrentControlSet\Services\<SERVICE>" /v Group /t REG_SZ /d "FSFilter Bottom" /f
```

### Automated tools
#### Example Windows Defender Antivirus & Endpoint
- What does it do
	- Modifies the `Altitude` values of the `WIMMount` and `npsvctrig` services, sets their `Start` type to `0` (boot start), and assigns them to the `FSFilter Bottom` group. This setup is intended to override or take precedence over the `MsSecFlt` and `WdFilter` minifilter drivers, which are part of Microsoft Defender Antivirus and Microsoft Defender for Endpoint (MDE).
- Link to code (Not published yet)

```
.\AltitudeTakeover.exe -e
```

- Note: Does not fully recover as the altitude won't be changed back! You gotta set these back manually!

```
.\AltitudeTakeover.exe -d

reg add "HKLM\SYSTEM\CurrentControlSet\Services\WIMMount\Instances\WIMMount" /v Altitude /t REG_SZ /d "180700" /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\npsvctrig\Instances\npsvctrig" /v Altitude /t REG_SZ /d "46000" /f
```

#### Example Sysmon
- What does it do
	- Modifies the `Altitude` values of the `WIMMount` services, sets their `Start` type to `0` (boot start), and assigns them to the `FSFilter Bottom` group. This setup is intended to override or take precedence over the `SysmonDrv`  minifilter driver from Sysmon.
- Link to code (Not published yet)

```
.\AltitudeTakeover.exe -e
```

- Note: Does not fully recover as the altitude won't be changed back! You gotta set these back manually!

```
.\AltitudeTakeover.exe -d

reg add "HKLM\SYSTEM\CurrentControlSet\Services\WIMMount\Instances\WIMMount" /v Altitude /t REG_SZ /d "180700" /f
```

## Network Telemetry
### Blocking EDR's traffic
- Block outgoing traffic stops alerts and telemetry to be send to the central server. Also stops sample submission for Cloud scanning.
- Block incoming traffic stops incoming updates, configurations, threat containment/quarantine actions and further threat hunting queries.
- Two Native Firewall Implementation Methods in Windows
	- Windows Defender Firewall
		- A built-in firewall in Windows that allows filtering per application, port, protocol, and direction.
		- Uses a high-level abstraction built on top of WFP.
		- Rules are managed via GUI, PowerShell, `netsh`, or COM interfaces like `INetFwPolicy2`.
	- Windows Filtering Platform
		- A kernel-mode packet filtering framework
		- Allows creation of highly detailed filtering policies at many layers of the networking stack (Transport, Application, Packet, etc.).
		- Often used by antivirus software, VPNs, and advanced networking tools.

#### Example Windows Defender Firewall blocking rules
- Blocks traffic of EDR processes using the built-in Windows Defender Firewall
- https://github.com/0xJs/BlockEDRTraffic

```
.\WindowsDefenderFirewall.exe -e
```

#### Example Windows Filtering Platform
- Blocks traffic of EDR processes using the built-in Windows Filtering Platform. This is more OPSEC safe!
- https://github.com/0xJs/BlockEDRTraffic

```
.\WindowsFilteringPlatform.exe -e
```

## Other attacks
### Token Downgrade
- Replacing target process token with system token.
	- Can be used for privilege escalation
	- Can be used to downgrade protection level of EDR disabling the EDR's functionality

#### Windbg
- [WinDbg – Stealing tokens](Windbg.md#stealing-tokens)

#### Vulnerable driver
- [Driver Attacks – Token Changer (Downgrade EDR)](Driver-Attacks.md#token-changer---downgrade-edr)