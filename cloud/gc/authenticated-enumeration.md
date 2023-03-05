# Authenticated enumeration
* [General](#General)
* [Enumeration through Google Cloud portal](#Enumeration-through-Google-Cloud-portal)
* [Enumeration using gcloud CLI](#Enumeration-using-gcloud-CLI)
  * [Authentication](#Authentication)
  * [Resource Hierarchy](#Resource-Hierarchy)
  * [Projects](#Projects)
  * [Service Accounts](#Service-accounts)
  * [IAM](#IAM)
  * [Virtual machines](#Virtual-machines)
  * [Storage Buckets](#Storage-Buckets)
  * [Webapps and SQL](#Webapps-and-SQL)
  * [Networking](#Networking)
  * [Containers](#Containers)
  * [Serverless](#Serverless)
* [Enumeration using Google Cloud API](#Enumeration-using-Google-Cloud-API)

## General
## Enumeration through Google Cloud portal
- Google Cloud login at https://console.cloud.google.com/
- Google Workspace admin login at https://admin.google.com/
- Google Workspace user access https://myaccount.google.com/
  - Mail https://mail.google.com/
  - Google Drive https://drive.google.com/
  - Contacts https://contacts.google.com/

## Enumeration using gcloud CLI
- Documentation: https://cloud.google.com/sdk/gcloud/reference
-  Most GCP instances have Google Cloud SDK installed
-  ```gcloud``` CLI tool for managing auth, config, and interacting with GCP services
-  ``` gsutil``` CLI tool for accessing GCP storage buckets

#### Gcloud services and commands
```
gcloud
```

### Authentication
#### User account 
- Login through the GUI with Username & Pass
```
gcloud auth login
```

#### Service account login
- Json key file
```
gcloud auth activate-service-account --key-file <JSON FILE>
```

#### User Account - Username & Pass - External application login
- Also known as Application Default Credential
- Login through the GUI with Username & Pass and creates `application_default_credentials.json`
```
gcloud auth application-default login
```

#### Service Account - External application
- Also known as Application Default Credential
- Used for Terraform for example
```
$env:GOOGLE_APPLICATION_CREDENTIALS="<PATH TO OF .json OF SERVICE ACCOUNT>"
dir env:
```

#### get the current user
```
gcloud auth list
```

#### Change between user
```
gcloud config set account <ACCOUNT>
```

#### Get config of all sessions/users
- Such as project set etc.
- Usefull if using multiple users
```
gcloud config list
```

### Resource Hierarchy
- Organization --> Folders --> Projects --> Resources

#### List google cloud organizations the user has access too
```
gcloud organizations list
```

#### List GCP folders
```
gcloud resource-manager folders list --organization <ORG ID>
```

#### List resources
- Required `cloudasset.googleapis.com` to be enabled for project
```
gcloud beta asset search-all-resources
```

### Projects
- All Google Cloud resources are in projects. When quering for resources it is limited to the projects. You gotta change projects to enumerate everything!

#### Get projects
```
gcloud projects list
```

#### Get hierachy of project
```
gcloud projects get-ancestors <PROJECT ID>
```

#### Set a project
```
gcloud config set project <PROJECT NAME> 
```

#### Get current project set
```
gcloud config get project
```

#### Gives a list of all APIs that are enabled in project
```
gcloud services list
```

#### Get information about project
```
gcloud projects describe <PROJECT ID>
```

### Service accounts
#### List service accounts on project level
```
gcloud iam service-accounts list
```

### IAM
- Three roletypes
  - Basic roles, provides broader access to Google Cloud resources - Owner, Editor, Viewer
  - Predefined roles, provides granular access to specific Google Cloud resources.
  - Custom Roles, provides custom access to Google Cloud resources.

#### Enumerate IAM policies set ORG-wide
```
gcloud organizations get-iam-policy <ORG ID>
```

#### Check IAM policy on project level
```
gcloud projects get-iam-policy <PROJECT ID> --flatten="bindings[].members" --filter="bindings.members=user:<USER EMAIL>" --format="value(bindings.role)" 
```

#### List all permission in custom role
```
gcloud iam roles describe <ROLE> --project <PROJECT ID>
```

#### List permissions of service account
```
gcloud iam service-accounts get-iam-policy <SERVICE ACCOUNT EMAIL>
```

### Repos
#### Get source code repos available to user
```
gcloud source repos list
```

#### Clone repo to home dir
```
gcloud source repos clone <repo_name>
```

### Virtual machines
#### List other compute instances in the same project
```
gcloud compute instances list
```

#### Get shell access to instance
```
gcloud beta compute ssh --zone "<region>" "<instance name>" --project "<project name>"
```

#### Puts public ssh key onto metadata service for project
```
gcloud compute ssh <local host>
```

#### Get access scopes if on an instance
```
curl http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes -H &#39;Metadata-Flavor:Google’
```

#### Use Google keyring to decrypt encrypted data
```
gcloud kms decrypt --ciphertext-file=encrypted-file.enc --plaintext-file=out.txt --key <crypto-key> --keyring <crypto-keyring> --location global
```

### Storage Buckets
#### List storage buckets
```
gsutil ls
```

#### List storage buckets recursively
```
gsutil ls -r gs://<bucket name>
```

### Webapps and SQL
#### List webapps
```
gcloud app instances list
```

#### List SQL instances
```
gcloud sql instances list
gcloud spanner instances list
gcloud bigtable instances list
```

#### List SQL databases
```
gcloud sql databases list --instance <instance ID>
gcloud spanner databases list --instance <instance name>
```

#### Export SQL databases and buckets
- First copy buckets to local directory
```
gsutil cp gs://bucket-name/folder/ .
```

#### Create a new storage bucket, change perms, export SQL DB
```
gsutil mb gs://<googlestoragename>
gsutil acl ch -u <service account> gs://<googlestoragename>
gcloud sql export sql <sql instance name> gs://<googlestoragename>/sqldump.gz --database=<database name>
```

### Networking
#### List networks
```
gcloud compute networks list
```

#### List subnets
```
gcloud compute networks subnets list
```

#### List VPN tunnels
```
gcloud compute vpn-tunnels list
```

#### List Interconnects (VPN)
```
gcloud compute interconnects list
```

### Containers
```
gcloud container clusters list
```

#### GCP Kubernetes config file ~/.kube/config gets generated when you are authenticated with gcloud and run:
```
gcloud container clusters get-credentials <cluster name> --region <region>
```

#### Get cluster info
- If successful and the user has the correct permission the Kubernetes command below can be used to get cluster info:
```
kubectl cluster-info
```

## Serverless
#### List cloud functions
```
gcloud functions list
```

#### GCP functions log analysis 
- May get useful information from logs associated with GCP functions
```
gcloud functions describe <function name>
gcloud functions logs read <function name> --limit <number of lines>
```

#### GCP Cloud Run analysis
- May get useful information from descriptions such as environment variables.
```
gcloud run services list
gcloud run services describe <service-name>
gcloud run revisions describe --region=<region> <revision-name>
```

## Enumeration using Google Cloud API
- Service Endpoint : https://[ServiceName].googleapis.com
- Documentation: https://developers.google.com/apis-explorer

#### Validate access token
```
curl https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=<ACCESS TOKEN>
```

#### Access Google API
```
curl -X Method -H “Authorization: Bearer $AccessToken” https://API-URL
```
