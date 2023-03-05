# Persistence
- App passwords
  - Good way to get around 2fa but are revoked on password changes
- Backup codes
  - Generate one-time passcodes that can be used for 2-step verifictation
-  API and service account tokens
  -  Create a new project on cloud.google.com
  -  Enable API access with scopes set to any resources you can
  
## Service Account
#### Create a new key for specified service account.
- Saves credentials in `key.json`
```
gcloud iam service-accounts keys create key.json --iam-account <SERVICE ACCOUNT ID>
```

#### Authenticate with key file
```
gcloud auth activate-service-account --key-file key.json
```
