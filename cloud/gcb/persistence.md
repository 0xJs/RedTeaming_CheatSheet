# Persistence
- App passwords
  - Good way to get around 2fa but are revoked on password changes
- Backup codes
  - Generate one-time passcodes that can be used for 2-step verifictation
-  API and service account tokens
  -  Create a new project on cloud.google.com
  -  Enable API access with scopes set to any resources you can
  -  or Create private key JSON file for service account
  -  ```gcloud iam service-accounts keys create --iam-account my-iamaccount@somedomain.com key.json```
