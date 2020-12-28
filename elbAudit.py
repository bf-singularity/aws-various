"""
Audit AWS ELB service for deletion protection
outputs to elbReport.csv
"""
import boto3
import json
import sys

def query_elbs(profile,region):
    returnString = ""
    print("[*] Querying " + region)
    session = boto3.Session(profile_name=profile, region_name=region)
    client = session.client('elbv2')
    try:
        elbs = client.describe_load_balancers()
    except:
        print("[!] Error querying " + region)
        return returnString

    #list should only contain app, netw, and gatew loadbalancers. Not classic loadbalancers bc we're calling elbv2 client
    for elb in elbs["LoadBalancers"]:
        arn = elb["LoadBalancerArn"]

        try:
            elbAttr = client.describe_load_balancer_attributes(LoadBalancerArn=arn)
        except:
            print("[!] Exception querying " + arn)
            elbAttr = ""

        delProt = next((item for item in elbAttr["Attributes"] if item["Key"] == "deletion_protection.enabled"),None)
        if delProt == None:
            print("[!] Exception for " + arn)
            delProt["Value"] == "Error"
        elif delProt["Value"] == "false":
            print("[!] Deletion protection not enabled on " + arn)
        returnString += ",%s,%s,%s\n" % (region,arn,delProt["Value"])
    return returnString

try:
    profile = sys.argv[1]
except:
    profile = "default"

#get account ID
session = boto3.Session(profile_name=profile, region_name="us-east-1")
client = session.client("sts")
response = client.get_caller_identity()
account = response["Account"]

#get regions
client = session.client('ec2')
response = client.describe_regions(AllRegions=True)
regions = []
for region in response["Regions"]:
    if region["OptInStatus"] != "not-opted-in":
        regions.append(region["RegionName"])

report = "Account,Region,ELB ARN,Deletion Protection Enabled\n"
# run through non-gov, default regions
for region in regions:
    report += account + query_elbs(profile,region)

#report
with open("elbReport.csv","w") as outFile:
    outFile.write(report)
