# Recon on the target
## Index

* [Recon tools](#Recon-tools)
* [Recon techniques](#Recon-techniques)
* [Azure](#Azure)
  * [Manually](#Manually)
  * [AADinternals](#AADinternals)
  * [Microburst](#Microburst)
  * [Valid emails](#Valid-emails)

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

### Recon employees
- Build a user list with linkedin
- Determine username scheme via public file metadata (PDF, DOCX, XLSX, etc)
  - Powermeta https://github.com/dafthack/PowerMeta
  - FOCA https://github.com/ElevenPaths/FOCA

### User enumeration
- Azure can be performed at https://login.microsoft.com/common/oauth2/token
- This endpoint tells you if a user exists or not
- Detect invalid users while password spraying with MSOL spray

## Azure
### Manually
#### Get if tenant is in use and if fedaration is in use.
- Federation with Azure AD or O365 enables users to authenticate using on-premises credentials and access all resources in cloud.
```
https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
https://login.microsoftonline.com/getuserrealm.srf?login=root@defcorphq.onmicrosoft.com&xml=1
```

#### Get the Tenant ID
```
https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
https://login.microsoftonline.com/defcorphq.onmicrosoft.com/.well-known/openid-configuration
```

### AADinternals
https://github.com/Gerenios/AADInternals
https://o365blog.com/aadinternals/

#### Import the AADinternals module
```
import-module .\AADInternals.psd1
```

#### Get all the information of the tenant
```
Invoke-AADIntReconAsOutsider -DomainName <DOMAIN>
```

####  Get tenant name, authentication, brand name (usually same as directory name) and domain name
```
Get-AADIntLoginInformation -UserName <RANDOM USER>@<DOMAIN>
```

#### Get tenant ID
```
Get-AADIntTenantID -Domain <DOMAIN>
```

#### Get tenant domains
```
Get-AADIntTenantDomains -Domain <DOMAIN>
```

## Microburst
#### Enumerate used services
- https://github.com/NetSPI/MicroBurst
- Edit the permutations.txt to add permutations such as career, hr, users, file and backup
```
Import-Module MicroBurst.psm1 -Verbose
Invoke-EnumerateAzureSubDomains -Base <SHORT DOMAIN NAME> -Verbose
```

#### Enumerate Azureblobs
- Add permutations to permutations.txt like common, backup, code in the misc directory.
```
Import-Module ./Microburst.psm1
Invoke-EnumerateAzureBlobs -Base <SHORT DOMAIN> -OutputFile azureblobs.txt
```

## Valid emails
#### Check for Email ID's
- https://github.com/LMGsec/o365creeper
- Could gather list of emails from something like harvester or hunter.io or smth and validate them!
- admin, root, test, contact (try those default for exam)
```
python o365creeper.py -f list_of_emails.txt -o validemails.txt
```
- Possible to use https://github.com/nyxgeek/onedrive_user_enum (Non-lab-tool)

