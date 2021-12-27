# Authenticated enumeration
## Index
* [Authentication](#Authentication)
* [Manual Enumeration](#Manual-enumeration)
  * [S3 buckets](#S3-buckets)
  * [Webapps & SQL](#Webapps-and-SQL)
  * [Serverless](#Serverless)
  * [Networking](#Networking)
* [Tools](#Tools)
  * [PACU](#PACU)
  * [WeirdAAL](#WeirdAAL)

## Authentication
- AWS Command Line https://aws.amazon.com/cli/
- use ```--profile=<NAME>``` to use a specific profile for executing the commands
 
#### Set AWS programmatic keys for authentication 
- use ```--profile=<name>``` for a new profile
```
aws configure
```

## Manual enumeration
#### Get basis account info
```
aws sts get-caller-identity
```

#### List EC2 instances
```
aws ec2 describe-instances --region <region>
```

#### List IAM users
```
aws iam list-users
```

#### List IAM roles
```
aws iam list-roles
```

#### List access keys for a user
```
aws iam list-access-keys --user-name <username>
```

### S3 buckets
#### List s3 buckets
```
aws iam list-roles
```

#### List the contents of an S3 bucket
```
aws s3 ls s3://<bucketname>/ 
```

#### Download contents of bucket
```
aws s3 sync s3://bucketname s3-files-dir
```

#### List EC2 instances
```
aws ec2 describe-instances
```

### Webapps and SQL
#### List WebApps
```
aws deploy list-applications
```

#### List AWS RDS (SQL)
```
aws rds describe-db-instances --region <region name>
```

Knowing the VPC Security Group ID you can query the firewall rules to determine connectivity potential

```
aws ec2 describe-security-groups --group-ids <VPC Security Group ID> --region <region>
```

### Serverless
#### List Lambda Functions
```
aws lambda list-functions --region <region>
```

#### Look at environment variables set for secrets and analyze code
```
aws lambda get-function --function-name <lambda function>
```

### Networking
#### List EC2 subnets
```
aws ec2 describe-subnets
```

#### List ec2 network interfaces
```
aws ec2 describe-network-interfaces
```

#### List DirectConnect (VPN) connections
```
aws directconnect describe-connections
```

## Tools
### PACU
#### Enumerate account information and permissions
```
run iam__enum_users_roles_policies_groups
run iam__enum_permissions
whoami
```

### WeirdAAL
#### Setup authentication with keys
```
cp env.sample .env
nano .env

#Add the following contents:
[default]
aws_access_key_id = <Access-key>
aws_secret_access_key = <Secret-access-key>
aws_session_token = <Session-Token>
````

#### Run recon_all module
```
python3 weirdAAL.py -m recon_all -t ssrf
```

#### List permissions
```
python3 weirdAAL.py -m list_services_by_key -t ssrf
```

#### List S3 buckets
```
python3 weirdAAL.py -m s3_get_bucket_policy -a <s3 bucket> -t ssrf
```

#### Download file from s3 bucket
```
python3 weirdAAL.py -m s3_download_file -a ‘<s3 bucket','admin-user.txt' -t ssrf
cat loot/<s3 bucket name>/admin-user.txt
```
