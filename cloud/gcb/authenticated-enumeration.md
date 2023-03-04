# Authenticated enumeration
* [General](#General)
* [Authentication](#Authentication)
* [Manual Enumeration](#Manual-Enumeration)
  * [Resource Hierarchy](#Resource-Hierarchy)
  * [User](#User)
  * [IAM](#IAM)
  * [Projects](#Projects)
  * [Virtual machines](#Virtual-machines)
  * [Storage Buckets](#Storage-Buckets)
  * [Webapps and SQL](#Webapps-and-SQL)
  * [Networking](#Networking)
  * [Containers](#Containers)
  * [Serverless](#Serverless)

## General

## Authentication
#### User identity login
```
gcloud auth login
```

#### Service account login
```
gcloud auth activate-service-account --key-file creds.json
```

## Manual Enumeration
-  Most GCP instances have Google Cloud SDK installed
-  ```gcloud``` CLI tool for managing auth, config, and interacting with GCP services
-  ``` gsutil``` CLI tool for accessing GCP storage buckets

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

### User
#### Get account information
```
gcloud config list
```

#### List accounts available to gcloud
```
gcloud auth list
```

### IAM
#### Enumerate IAM policies set ORG-wide
```
gcloud organizations get-iam-policy <ORG ID>
```

### Projects
#### Get projects
```
gcloud projects list
```

#### Get hierachy of project
```
gcloud projects get-ancestors <PROJECT ID>
```

#### Set a different project
```
gcloud config set project <PROJECT NAME> 
```

#### Gives a list of all APIs that are enabled in project
```
gcloud services list
```

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
#### GCP functions log analysis 
- May get useful information from logs associated with GCP functions
```
gcloud functions list
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

