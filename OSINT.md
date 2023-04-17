# OSINT
- The page is bare, really need to do a OSINT course ;)

* [General](#General)
* [Google fu / dorks](#Google-fu-/-dorks)
* [Host Information](#Host-Information)
  * [Mail](#Mail)
* [Hunting usernames](#Hunting-usernames)
* [Hunting passwords & credentials](#Hunting-passwords-&-credentials)
* [Hunting for personal information](#Hunting-for-personal-information)
* [Web](#Web)
  * [General Info](#General-Info)
  * [Hunting subdomains](#Hunting-subdomains)
* [Image](#Image)
  * [Reverse Image Searching](#Reverse-Image-Searching)
  * [EXIF Data](#EXIF-Data)
* [File](#File)
* [Social media](#Social-media)
* [Business](#Business)
* [Wireless](#Wireless)
* [Cloud](#Cloud)
  * [Azure](#Azure) 
* [Automating-OSINT-Example](#Automating-OSINT-Example)

## General
- Two main facets of recon: Organisational and technical.
- Gathering can be done passively or actively.

#### OSINT Frameworks
- https://github.com/lanmaster53/recon-ng
- https://www.maltego.com/
- https://www.spiderfoot.net/

#### Other tools
- https://hunch.ly/

#### Search engines
- https://www.google.com/
- https://www.bing.com/
- https://duckduckgo.com/
- https://www.baidu.com/
- https://yandex.com/

#### Create Sockpuppet / alias
- Settings up a anonymous sockpuppet
- https://www.reddit.com/r/OSINT/comments/dp70jr/my_process_for_setting_up_anonymous_sockpuppet/

## Google fu / dorks
- https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06
- https://www.exploit-db.com/google-hacking-database

#### Example
```
site:hackdefense.com filetype:pdf
```

#### Specific website
```
searchterm site:example.com
```

#### Search for specific string
```
"search this string"
``` 

## Host Information
#### Get IP Adresses of a domain name
```
dig <DOMAIN> +short
```

#### Check whois of each IP
- Check who owns the IP, where is it hosted?
```
whois <IP>
```

### Mail
#### Check spf, dkim, dmarc etc
- https://github.com/a6avind/spoofcheck
```
./spoofcheck.py <DOMAIN>
```

## Finding Email adresses
#### Discovering email adresses or pattern
- https://hunter.io
- https://phonebook.cz

#### Verify email-adres
- https://tools.emailhippo.com/
- https://email-checker.net/validate

#### theHarvester
```
theHarvester -d <DOMAIN> -b google -l 500
```

## Hunting usernames
- https://namechk.com/
- https://whatsmyname.app/
- https://namecheckup.com/

#### WhatsMyName
- https://github.com/WebBreacher/WhatsMyName
```
whatsmyname -u <USERNAME>
```

#### Sherlock
- https://github.com/sherlock-project/sherlock
```
sherlock <USERNAME>
```

## Hunting passwords & credentials
- https://www.dehashed.com/
- https://www.weleakinfo.to/
- https://leakcheck.io/
- https://snusbase.com/
- https://scylla.sh/
- https://haveibeenpwned.com/

#### Breachparse
- https://github.com/hmaverickadams/breach-parse
```
./breach-parse.sh @<DOMAIN> password.txt
```

#### H8mail
- https://github.com/khast3x/h8mail
```
h8mail -t <EMAIL>
```

#### Query without API keys against local breachcompilation
```
h8mail -t <EMAIL> -bc "/opt/breach-parse/BreachCompilation/" -sk
```

#### Check for hashes
- https://hashes.org

#### Leaked credentials on github
- https://github.com/zricethezav/gitleaks
```
gitleaks --repo-url=<GIT REPO URL> -v
```

## Hunting for personal information
- https://www.whitepages.com/
- https://www.truepeoplesearch.com/
- https://www.fastpeoplesearch.com/
- https://www.fastbackgroundcheck.com/
- https://webmii.com/
- https://peekyou.com/
- https://www.411.com/
- https://www.spokeo.com/
- https://thatsthem.com/

### Search phone numbers
- https://www.truecaller.com/
- https://calleridtest.com/
- https://infobel.com/
- Can also check out logins, forget password and check for phone number!

#### phoneinfoga
- https://github.com/sundowndev/phoneinfoga
```
phoneinfoga scan -n <COUNTRYCODE><PHONENUMBER>
```

## Web
### General Info
- whois / dns etc
- https://centralops.net/co/
- https://spyonweb.com/
- https://dnslytics.com/reverse-ip
- https://viewdns.info/
- https://spyonweb.com/
- https://www.virustotal.com/
- Alert on changes on website: https://visualping.io/
- Look for backlinks: http://backlinkwatch.com/index.php

#### Shodan.io
- https://shodan.io/

#### Check old versions of the website / files
- https://web.archive.org/

### Hunting subdomains
- Script that uses multiple tools to enumerate subdomains: https://github.com/Gr1mmie/sumrecon

#### Amass - Best tool
- https://github.com/OWASP/Amass
```
amass enum -d example.com
```

#### Dnsdumpster
- Gui tool: https://dnsdumpster.com/

#### Sublister
```
sublister -domain <DOMAIN>
```

#### crt.sh
- https://crt.sh

#### Dnscan
- https://github.com/rbsec/dnscan
```
dnscan.py <DOMAIN>
```

#### DNSrecon
```
python3 dnsrecon.py -d <DOMAIN>
```

#### Gobuster
- https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS
```
gobuster dns -d <target domain> -w <wordlist>
```

#### Other tools
- https://pentest-tools.com/information-gathering/find-subdomains-of-domain#
- https://spyse.com/

### Discover Website Technologies
- https://builtwith.com/
- https://addons.mozilla.org/nl/firefox/addon/wappalyzer/

#### Whatwheb
```
whatweb <URL>
```

## Image
### Reverse Image Searching
- https://images.google.com/
- https://yandex.com/images/
- https://tineye.com/
- Drag the image in

### EXIF Data
#### Online
- Location data is already way more secure, but might still get something.
- http://exif.regex.info/exif.cgi

#### Exiftool
```
exiftool <img>
```

#### Identifying Geographical Locations
- https://www.geoguessr.com/
- https://somerandomstuff1.wordpress.com/2019/02/08/geoguessr-the-top-tips-tricks-and-techniques/

## File
- Powermeta https://github.com/dafthack/PowerMeta
- FOCA https://github.com/ElevenPaths/FOCA

## Social media
### Twitter
- https://twitter.com/search-advanced
- https://socialbearing.com/
- https://www.twitonomy.com/
- http://sleepingtime.org/
- https://mentionmapp.com/
- https://tweetbeaver.com/
- http://spoonbill.io/
- https://tinfoleak.com/
- https://tweetdeck.com/

#### Twint
- https://github.com/twintproject/twint
```
twint -u <USER> -s <STRING>
```

### Facebook
- https://sowdust.github.io/fb-search/
- https://intelx.io/tools?tab=facebook

### Instagram
- https://wopita.com/
- https://codeofaninja.com/tools/find-instagram-user-id/
- https://www.instadp.com/
- https://imginn.com/

### Snapchat
- https://map.snapchat.com

### Reddit
- https://www.reddit.com/search

### Linkedin
- https://www.linkedin.com/

## Business
- Check them out on LinkedIn / Twitter / Social media etc.
- https://opencorporates.com/
- https://www.aihitdata.com/

## Wireless
- https://wigle.net/

## General
1. Traditional host discovery still applies
2. After host discovery resolve all names, then perforn whois lookups to determine where are they hosted.
3. Microsoft, Amazon, Google IP space usually indicates cloud service usage.
4. Check MX records. These can show cloud-hosted mail providers

## Cloud
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

#### Azure / O365 usage
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

### Enumerate public resources
#### Cloud enum
- Possible to use multiple `-k` keywords.
```
python3 cloud_enum.py -k <KEYWORD>
```

### Azure
#### Check if tenant is in use and if fedaration is in use.
- Federation with Azure AD or O365 enables users to authenticate using on-premises credentials and access all resources in cloud.
```
https://login.microsoftonline.com/getuserrealm.srf?login=<USER>@<DOMAIN>&xml=1
```

#### Get the Tenant ID
```
https://login.microsoftonline.com/<DOMAIN>/.well-known/openid-configuration
```

### AADinternals
- https://github.com/Gerenios/AADInternals
- https://o365blog.com/aadinternals/

#### Import the AADinternals module
```
import-module .\AADInternals.psd1
```

#### Get all the information of the tenant
```
Invoke-AADIntReconAsOutsider -DomainName <DOMAIN>
```

#### Get tenant name, authentication, brand name (usually same as directory name) and domain name
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

### Enumerate used services
#### Enumerate Azure subdomains
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

### Valid emails
#### Check for Email ID's
- https://github.com/LMGsec/o365creeper
- Could gather list of emails from something like harvester or hunter.io or smth and validate them!
- admin, root, test, contact (try those default for exam)
```
python o365creeper.py -f list_of_emails.txt -o validemails.txt
```
- Possible to use https://github.com/nyxgeek/onedrive_user_enum (Non-lab-tool)

## Automating OSINT Example
```
#!/bin/bash

domain=$1
RED="\033[1;31m"
RESET="\033[0m"

info_path=$domain/info
subdomain_path=$domain/subdomains
screenshot_path=$domain/screenshots

if [ ! -d "$domain" ];then
    mkdir $domain
fi

if [ ! -d "$info_path" ];then
    mkdir $info_path
fi

if [ ! -d "$subdomain_path" ];then
    mkdir $subdomain_path
fi

if [ ! -d "$screenshot_path" ];then
    mkdir $screenshot_path
fi

echo -e "${RED} [+] Checkin' who it is...${RESET}"
whois $1 > $info_path/whois.txt

echo -e "${RED} [+] Launching subfinder...${RESET}"
subfinder -d $domain > $subdomain_path/found.txt

echo -e "${RED} [+] Running assetfinder...${RESET}"
assetfinder $domain | grep $domain >> $subdomain_path/found.txt

#echo -e "${RED} [+] Running Amass. This could take a while...${RESET}"
#amass enum -d $domain >> $subdomain_path/found.txt

echo -e "${RED} [+] Checking what's alive...${RESET}"
cat $subdomain_path/found.txt | grep $domain | sort -u | httprobe -prefer-https | grep https | sed 's/https\?:\/\///' | tee -a $subdomain_path/alive.txt

echo -e "${RED} [+] Taking dem screenshotz...${RESET}"
gowitness file -f $subdomain_path/alive.txt -P $screenshot_path/ --no-http
```
