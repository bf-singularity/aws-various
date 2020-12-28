"""
Tests which of the IAM users can assume a given role. Role can be in same AWS account as users, or different account (crossAccountAssumeRole)
Outputs to console. 
"""
import boto3
import sys
import json
import argparse

# simulate assuming the given AWS role as the current user
def test_for_allow(profile, arn, role):
    session = boto3.Session(profile_name=profile, region_name="us-east-1")
    client = session.client("iam")
    response = client.simulate_principal_policy(PolicySourceArn=arn, ActionNames=["sts:AssumeRole"], ResourceArns=[role])
    for results in response["EvaluationResults"]:
        if results["EvalDecision"] == "allowed":
            return True,results["MatchedStatements"]
        else:
            return False, []

#Parse command line arguments    
parser = argparse.ArgumentParser()
parser.add_argument("--profile",help="The AWS profile to run against")
parser.add_argument("--role",help="The IAM role to attempt to assume")
arguments = parser.parse_args()

if not arguments.profile:
    arguments.profile = "default"
if not arguments.role:
    # a role for testing user policies on sts:AssumeRole:*. This role exists in my AWS account and has no permissions, but can be assumed by anyone. 
    # if an IAM user in some other account can assume this role, they must have sts:AssumeRole:*
    arguments.role = "arn:aws:iam::199054426378:role/CrossAccountTestPolicy"

profile = arguments.profile
role = arguments.role
#get users
session = boto3.Session(profile_name=profile, region_name="us-east-1")
client = session.client("iam")
response = client.list_users()

allUsers = []
allUsers = response["Users"]
if "IsTruncated" in response and response["IsTruncated"] == True:
    while response["IsTruncated"] == True:
        marker = response["Marker"]
        response = client.list_users(Marker=marker)
        allUsers += response["Users"]

for user in allUsers:
    print("[*] Testing user " + user["UserName"])
    arn = user["Arn"]
    result, matchedStatements = test_for_allow(profile, arn,role)
    if result == True:
        print("[!] User " + user["UserName"] + " is allowed to assume " + role + " according to these policies:")
        for statement in matchedStatements:
            print("  - " + statement["SourcePolicyId"])
