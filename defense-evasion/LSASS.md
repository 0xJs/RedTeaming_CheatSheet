## LSASS
- [LSASS Protections](#lsass-protections)
	- [Enumerate LSASS protections](#enumerate-lsass-protections)
	- [Process protection level](#Process-protection-level)
		- [Remove Process protections](#remove-process-protections)
	- [Credential Guard](#credential-guard)
		- [Disable credential guard](#disable-credential-guard)
- [LSASS dumping](#lsass-dumping)
	- [General dumping commands](#General-dumping-commands)
	- [Custom Tools](#Custom-Tools)
		- [HookMiniDump](#hookminidump)
		- [CustomMiniDump](#customminidump)

## LSASS protections

### Enumerate LSASS protections
- Enumerates process protection of LSASS, CredentialGuard and other security features
- https://github.com/0xJs/EnumMitigations/blob/main/README.md

```
.\EnumMitigations.exe
```

## Process protection level
- Adds Protection level to a process and resides in the kernel in the `Protection` field as 1 byte value in the `EPROCESS` structure. Blocks untrusted tools (e.g. Mimikatz) from reading LSASS memory.
- Configuration
	- Automatically enabled on Win11 22H2 [link](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection#automatic-enablement)
	- Can be enabled by configured the registry key `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa` to 
		- `1` - This value enables `0x41` `PS_PROTECTED_LSA_LIGHT` - with a UEFI variable,
		- `2` - This value enables `0x41` PS_PROTECTED_LSA_LIGHT - without a UEFI variable and only enforced on Windows 11 build 22H2 and later
- The following protection levels exist

| Protection Level                | Value | Signer           | Type                |
| ------------------------------- | ----- | ---------------- | ------------------- |
| PS_PROTECTED_SYSTEM             | 0x72  | WinSystem (7)    | Protected (2)       |
| PS_PROTECTED_WINTCB             | 0x62  | WinTcb (6)       | Protected (2)       |
| PS_PROTECTED_WINDOWS            | 0x52  | Windows (5)      | Protected (2)       |
| PS_PROTECTED_AUTHENTICODE       | 0x12  | Authenticode (1) | Protected (2)       |
| PS_PROTECTED_WINTCB_LIGHT       | 0x61  | WinTcb (6)       | Protected Light (1) |
| PS_PROTECTED_WINDOWS_LIGHT      | 0x51  | Windows (5)      | Protected Light (1) |
| PS_PROTECTED_LSA_LIGHT          | 0x41  | Lsa (4)          | Protected Light (1) |
| PS_PROTECTED_ANTIMALWARE_LIGHT  | 0x31  | Antimalware (3)  | Protected Light (1) |
| PS_PROTECTED_AUTHENTICODE_LIGHT | 0x11  | Authenticode (1) | Protected Light (1) |

#### Check if RunasPPL is configured
- `1` - This value enables `0x41` `PS_PROTECTED_LSA_LIGHT` - Also known as standard protected LSASS.

```
reg query HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v RunAsPPL
```

### Remove Process protections

#### Windbg
- [WinDbg section](Windbg.md)

#### Vulnerable driver
- [Driver Attacks – Protection Changer](Driver-Attacks.md#protection-changer)

### Change process protection before dumping
- It is also possible to dump `lsass.exe` by changing the protection level of the current process to `0x72`

#### Vulnerable driver
- [Driver Attacks – Protection Changer](Driver-Attacks.md#protection-changer)

### Credential Guard
- Isolates LSASS secrets using Virtualization-Based Security (VBS). Secrets such as NTLM-hashes and TGT's are now stored in `lsasio.exe`.
- Enabled by default in Windows 11 22H2+ and Windows Server 2025
- Requires UEFI, Secure Boot, and VBS (Virtualization-Based Security) to be active.
- On enterprise-joined or AAD-joined Windows 11 22H2+ systems, Credential Guard is **enabled by default** unless explicitly disabled.

#### Check if credential guard is configured
- Checks if credential guard is specifically configured

```
(Get-ComputerInfo).DeviceGuardSecurityServicesConfigured -contains "CredentialGuard"
```

#### Check if credential guard is running
- Checks if credential guard is running. It can be running by default without it being configured.

```
(Get-ComputerInfo).DeviceGuardSecurityServicesRunning -contains "CredentialGuard"
```

### Disable credential guard
#### Simple POC
- What does it do
	- Checks if process is running in High Integrity and EnableDebugPrivilege is enabled
	- Calculates and prints offsets by downloading symbols from the internet as in EDRSandBlast project
	- Patches Wdigest by changing the value of UseLogonCredential and CredGuardEnabled
		- `CredGuardEnabled` = `0` and `UseLogonCredential` = `1` allows the credentials to be stored as cleartext
		- `CredGuardEnabled` = `1` or `UseLogonCredential` = `0` forces the credentials to be stored as session only
- Link to code (Not published yet)

```
.\CredentialGuardDisabler.exe -d
```

#### NativeBypassCredGuard
- https://github.com/ricardojoserf/NativeBypassCredGuard/tree/main
- Uses the NTAPI only

```
.\NativeBypassCredGuard.exe patch true
```

## LSASS dumping
#### General dumping commands
- [Dumping LSASS](windows-ad/Post-Exploitation.md#dumping-lsass)

### Custom Tools
#### HookMiniDump
- `MiniDumpWriteDump` with `NtWriteFile` hooking to XOR the lsass dump
- What does it do
	- Checks if process is running in High Integrity and EnableDebugPrivilege is enabled
	- Get remote process handle to lsass.exe
	- Create file for memory dumping
	- Installs hook for `NtWriteFile` which adds XOR encryption of the buffer using the MinHook library
	- Call [MiniDumpWriteDump](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/nf-minidumpapiset-minidumpwritedump) to dump lsass.exe memory, which calls the hooked `NtWriteFile`
	- Unhook and cleanup
- Link to code (Not published yet)

```
.\lsass_dump_hookMinidump.exe
```

#### CustomMiniDump
- https://doxygen.reactos.org/d8/d5d/minidump_8c_source.html
- What does it do
	- Checks if process is running in High Integrity and EnableDebugPrivilege is enabled
	- Get remote process handle to lsass.exe
	- Create file for memory dumping
	- Call custom `MiniDumpWriteDump` from reactos to dump lsass.exe memory including XOR encryption
- Link to code (Not published yet)

```
.\lsass_dump_customMinidump.exe
```