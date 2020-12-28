# aws-various
Various AWS scripts

## Newer Scripts (12/2020)
### assumeRoleTest.py
Tests which of the IAM users can assume a given role. Role can be in same AWS account as users, or different account (crossAccountAssumeRole)

### country.py
Runs through security groups and checks to see if they contain IP addresses in the ingress or egress list that belong to a specified country

### crossAccountAudit.py
Looks for roles that can be assumed by other AWS accounts, and checks to see if they are protected by an external ID or MFA

### elbAudit.py
Audit AWS ELB service for deletion protection

### findAssumableRoles.py
Searches AWS account for roles that can be assumed by users of a second AWS account

### rdsAudit.py
Audit AWS RDS service for Backup Retention Period, Multi-AZ, and Auto-Minor-Version Upgrade settings

### redshiftAudit.py
Audit AWS RedShift service for Audit Logging, User Activity Logging, Parameter Group, Encryption at Rest, and Encryption in Transit settings

### s3Audit.py
Audit AWS S3 service for Versioning, MFA Delete, Encryption Rules, Logging Enabled, and HTTPS Enforced settings

## Older Scripts (may not be useful anymore or even work depending on API changes)
### awsGetCredReport.sh
Just uses the API to download IAM credential report

### awsIamCheck.py
Audits downloaded IAM credential report for security violations on user accounts, such as users that have not been used in over a year, users with multiple API keys, etc. 

### awsPrivateIPs.py
Gets all private AWS IPs from EC2 instances. 

### awsPublicIps.py
Gets all public AWS IPs from EC2 instances. 

### awsRoute53.sh
Exports Route53 Information

### awsSgCheck.py
parse out the EC2 security groups that permit access to ports to 0.0.0.0/0
