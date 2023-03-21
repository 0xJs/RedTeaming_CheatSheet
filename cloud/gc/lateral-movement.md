# Lateral Movement
## Index
* [GCP Web console](#GCP-Web-console)
* [Gcloud CLI](#Gcloud-CLI)
  * [Access tokens](#Access-tokens)
* [GCP to Workspace](#GCP-to-Workspace)

## GCP Web console
- Sometimes GUI access might be desirable
- Only available to user accounts, not service accounts

#### Try to add a new editor to a project
```
gcloud projects add-iam-policy-binding <project name> --member user:<email address> --role roles/editor
```

## To other projects
### Take over service accounts
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

#### List projects
```
gcloud projects list
```

## Gcloud CLI
### Acess tokens
#### Inject access token in gcloud CLI
- Use `-D` to delete the access token
- https://github.com/RedTeamOperations/GCPTokenReuse
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

#### Access token parameter
- Save acces token in file and use the `--access-token-file=` parameter with gcloud CLI

### Accounts
#### Change account
```
gcloud config set account <ACCOUNT>
```

#### Account parameter
- use the parameter `--account <ACCOUNT` to execute commands with that account.

## GCP to Workspace
### Domain wide delegation
- https://gitlab.com/gitlab-com/gl-security/threatmanagement/redteam/redteam-public/gcp_misc/-/raw/master/gcp_delegation.py
