# Lateral Movement
## Index
* [GCP Web console](#GCP-Web-console)

## GCP Web console
- Sometimes GUI access might be desirable
- Only available to user accounts, not service accounts

#### Try to add a new editor to a project
```
gcloud projects add-iam-policy-binding <project name> --member user:<email address> --role roles/editor
```
