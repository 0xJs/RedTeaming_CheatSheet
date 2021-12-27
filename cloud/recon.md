# Recon on the target
## Recon steps for cloud asset discovery
1. Traditional host discovery still applies
2. After host discovery resolve all names, then perforn whois lookups to determine where are they hosted.
3. Microsoft, Amazon, Google IP space usually indicates cloud service usage.
4. Check MX records. These can show cloud-hosted mail providers

## Recon tools
- Recon-NG https://github.com/lanmaster53/recon
- OWASP Amass https://github.com/OWASP/Amass 
- Spiderfoot https://www.spiderfoot.net/ 
- Gobuster https://github.com/OJ/gobuster 
- Sublist3r https://github.com/aboul3la/Sublist3r
- Use search engine, bing, google are good places to start.
- Certificate transparency https://crt.sh/
- Shodan https://shodan.io
  - Query examples: org:"Target name", net:"CIDR Range", PORT:"443" 
- Censys https://censys.io
- Hackertarget https://hackertarget.com/
- Threatcrowd https://www.threatcrowd.org/
- DNSDumpster https://dnsdumpster.com/
- ARIN Searches https://whois.arin.net/ui/

## Recon techniques
### Finding subdomains
- Check DNS Dumpster https://dnsdumpster.com/

#### Bruteforce subdomains
- https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
```
gobuster dns -d <target domain> -w <wordlist>
```
### Check cloud usage
#### Check for IP Netblocks
- Azure Netblocks
  - Public: https://www.microsoft.com/en-us/download/details.aspx?id=56519 
  - US Gov: http://www.microsoft.com/en-us/download/details.aspx?id=57063 
  - Germany: http://www.microsoft.com/en-us/download/details.aspx?id=57064 
  - China: http://www.microsoft.com/en-us/download/details.aspx?id=57062
- AWS Netblocks
  - https://ip-ranges.amazonaws.com/ip-ranges.json
- GCP Netblocks
  - https://www.gstatic.com/ipranges/cloud.json

#### ip2provider
- https://github.com/oldrho/ip2provider
```
cat iplist.txt | python ip2provider.py
```

#### O365 usage
- Add domain to following url, if exists there is a tenant: 
```
https://login.microsoftonline.com/<TARGET DOMAIN>/v2.0/.well-known/openid-configuration
```

#### Google Workspace Usage
- Try to authenticate with a valid company email adress at gmail
- https://accounts.google.com/

#### AWS usage
- Check if any resources are being loaded from S3 buckets
- Using burp, navigate the webapp and check for any calls to ```https://[bucketname].s3.amazonaws.com ``` or  ```• https://s3-[region].amazonaws.com/[Org Name]```

#### Box.om usage
- Look for any login portals
- https://companyname.account.box.com

## Recon employees
- Build a user list with linkedin
- Determine username scheme via public file metadata (PDF, DOCX, XLSX, etc)
  - Powermeta https://github.com/dafthack/PowerMeta
  - FOCA https://github.com/ElevenPaths/FOCA

## User enumeration
- Azure can be performed at https://login.microsoft.com/common/oauth2/token
- This endpoint tells you if a user exists or not
- Detect invalid users while password spraying with MSOL spray

## Password spraying
#### Azure password spray
- https://github.com/dafthack/MSOLSpray
```
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList validemails.txt -Password <PASSWORD> -Verbose
```

## Find data in public storage
- https://github.com/initstring/cloud_enum can scan all three cloud services for multiple services.

#### Public azure blobs
- https://github.com/NetSPI/MicroBurst
```
Invoke-EnumerateAzureBlobs –Base <base name>
```

#### Public AWS blobs
- https://github.com/RhinoSecurityLabs/pacu

#### Public Google Storage Buckets
- https://github.com/initstring/cloud_enum
