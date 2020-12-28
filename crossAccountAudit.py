"""
This script looks for roles that can be assumed by other AWS accounts, and checks to see if they are protected by an external ID or MFA
Outputs to console. Does not print to report file at the moment. 
"""

import boto3
import sys
import json

#get account ID
try:
    profile = sys.argv[1]
except:
    profile = "default"

session = boto3.Session(profile_name=profile, region_name="us-east-1")
client = session.client("sts")
response = client.get_caller_identity()
account = response["Account"]

#boto session - list-roles()
client = session.client("iam")
response = client.list_roles()

allRoles = []
allRoles = response["Roles"]
if "IsTruncated" in response and response["IsTruncated"] == True:
    while response["IsTruncated"] == True:
        marker = response["Marker"]
        response = client.list_roles(Marker=marker)
        allRoles += response["Roles"]


searchString = "arn:aws:iam::"
crossAccountRoles = [] #the roles that can be assumed by users in another account
counter = 1
for role in allRoles:
    print("Querying role " + str(counter) + "/" + str(len(allRoles)) + ": " + role["RoleName"])
    crossAccount = False
    name = role["RoleName"]
    assumeRolePolicy = role["AssumeRolePolicyDocument"]
    for statement in assumeRolePolicy["Statement"]:
        if statement["Effect"] == "Allow":
            for k,v in statement["Principal"].items():
                if type(v) == list: #can be list
                    for principal in v:
                        if principal.find(searchString) != -1 and principal[13:25] != account and role["Arn"] not in crossAccountRoles:
                             print("[!] Role " + role["RoleName"] + " can be assumed by users of account " + principal[13:25])
                             crossAccount = True
                else: #can also be string
                    if v.find(searchString) != -1 and v[13:25] != account:
                        print("[!] Role " + role["RoleName"] + " can be assumed by users of account " + v[13:25])
                        crossAccount = True
    
        if crossAccount == True:
            if "Condition" in statement and statement["Condition"]:
                if "StringEquals" in statement["Condition"] and "sts:ExternalId" in statement["Condition"]["StringEquals"]:
                    print("[*] Role is protected by external ID")
                elif "Bool" in statement["Condition"] and "aws:MultiFactorAuthPresent" in statement["Condition"]["Bool"] and statement["Condition"]["Bool"]["aws:MultiFactorAuthPresent"] == "true":
                    print("[*] Role is protected by MFA")
            else:
                print("[!] No condition on Cross Account Assumable Role")
                crossAccountRoles.append(role["Arn"])
        
    counter += 1

print("\nThe following roles can be assumed from another AWS account and are not protected by MFA or an external ID:")
for role in crossAccountRoles:
    print(role)
