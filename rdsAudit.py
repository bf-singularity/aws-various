"""
Audit AWS RDS service for Backup Retention Period, Multi-AZ, and Auto-Minor-Version Upgrade settings
Outputs to rdsAudit.csv
Also outputs some findings to console while it's running
"""
import boto3
import sys
import json

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

reportString = "AWS Account ID,Region, RDS Instance, Backup Retention Period, Multi-AZ,Auto-Minor-Version Upgrade"
for region in regions:
    print("[*] Querying region " + region)
    client=session.client("rds")
    response = client.describe_db_instances()

    allRds = []
    allRds = response["DBInstances"]
    if "Marker" in response: #truncated response from AWS
        while "Marker" in response:
            marker = response["Marker"]
            response = client.describe_db_instances(Marker=marker)
            allRds += response["DBInstances"]

    for rds in allRds:
        reportString += "\n" + account + "," + region + "," + rds["DBInstanceIdentifier"] + "," + str(rds["BackupRetentionPeriod"]) + "," + str(rds["MultiAZ"]) + "," + str(rds["AutoMinorVersionUpgrade"])
        if rds["BackupRetentionPeriod"] >= 7:
            print("[!] " + rds["DBInstanceIdentifier"] + " has a short backup retention period")
        if rds["MultiAZ"] == False:
            print("[!] " + rds["DBInstanceIdentifier"] + " is not replicated to another AZ")
        if rds["AutoMinorVersionUpgrade"] == False:
            print("[!] " + rds["DBInstanceIdentifier"] + " has auto-minor-version upgrade disabled")

with open("rdsAudit.csv","w") as outFile:
    outFile.write(reportString)
