# Lateral Movement
## Index
* [GCP Web console](#GCP-Web-console)
* [Access tokens](#Access-tokens)
* [GCP to Workspace](#GCP-to-Workspace)

## GCP Web console
- Sometimes GUI access might be desirable
- Only available to user accounts, not service accounts

#### Try to add a new editor to a project
```
gcloud projects add-iam-policy-binding <project name> --member user:<email address> --role roles/editor
```

## Acess tokens
#### Inject access token in gcloud CLI
- Use `-D` to delete the access token
```
python3 /opt/gc/GCPTokenReuse/Gcp-Token-Updater.py -I --access-token "<ACCESS TOKEN>" --account-name <ACCOUNT EMAIL>
```

#### List sessions
```
gcloud auth list
```

#### Change user
```
gcloud config set account <ACCOUNT EMAIL>
```

#### Use raw access token
- Save acces token in file and use the `--access-token-file=` parameter with gcloud CLI

## GCP to Workspace
### Domain wide delegation
- https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_misc/-/raw/master/gcp_delegation.py
