"""
Searches AWS account for roles that can be assumed by users of a second AWS account (provided as second argument on command line)
Outputs to console. Does not generate a report file at the moment. 
"""
import boto3
import sys
import json

# Search the principal section of policy statement for the given AWS account ID
def findString(principal, name, searchAccount, assumableRoles, statement):
    if principal.find(searchAccount) != -1:
        assumableRoles.append(name)
        print("[!] " + name + " can be assumed by AWS Account " + searchAccount + ":")
        print(statement)
        return assumableRoles

try:
    searchAccount = sys.argv[1] ##the AWS account ID to search for
except:
    print("Provide an AWS Account ID to search the policies for")
    exit(0)

try:
    profile = sys.argv[2]
except:
    profile = "default"

# get IAM roles
session = boto3.Session(profile_name=profile, region_name="us-east-1")
client = session.client("iam")
response = client.list_roles()

allRoles = []
allRoles = response["Roles"]
if "IsTruncated" in response and response["IsTruncated"] == True:
    while response["IsTruncated"] == True:
        marker = response["Marker"]
        response = client.list_roles(Marker=marker)
        allRoles += response["Roles"]

assumableRoles = [] #the roles that can be assumed by the searchAccount
for role in allRoles:
    name = role["RoleName"]
    assumeRolePolicy = role["AssumeRolePolicyDocument"]
    for statement in assumeRolePolicy["Statement"]:
        if statement["Effect"] == "Allow":
            for k,v in statement["Principal"].items():
                if type(v) == list: #can be list
                    for principal in v:
                        if principal.find(searchAccount) != -1:
                            assumableRoles = findString(principal, name, searchAccount, assumableRoles, statement)
                else: #can also be string
                    if v.find(searchAccount) != -1:
                        assumableRoles = findString(v, name, searchAccount, assumableRoles, statement)
                    
for role in assumableRoles:
    print(role)
