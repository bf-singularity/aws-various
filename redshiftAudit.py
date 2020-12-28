"""
Audit AWS RedShift service for Audit Logging, User Activity Logging, Parameter Group, Encryption at Rest, and Encryption in Transit settings
redshiftAudit.csv
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


reportString = "AWS Account ID,Region,RedShift Cluster, Audit Logging, User Activity Logging, Parameter Group, Encryption at Rest, Encryption in Transit"
paramGroups = {}
for region in regions:
    session = boto3.Session(profile_name=profile, region_name=region)
    print("[*] Querying " + region)
    client = session.client("redshift")
    response = client.describe_clusters()
    print("    " + str(len(response["Clusters"])) + " clusters found in " + region)

    for cluster in response["Clusters"]:
        clusterID = cluster["ClusterIdentifier"]
        response = client.describe_logging_status(ClusterIdentifier=clusterID)

        # logging
        if "LoggingEnabled" in response and response["LoggingEnabled"] == True:
            reportString += "\n" + account + "," + region + "," + clusterID + ",Enabled"
        else:
           reportString += "\n" + account + "," + region + "," + clusterID + ",Disabled"

        for parameterGroup in cluster["ClusterParameterGroups"]:
            paramGroup = parameterGroup["ParameterGroupName"]
            if paramGroup not in paramGroups:
                paramGroups[paramGroup] = client.describe_cluster_parameters(ParameterGroupName=paramGroup)

        for param in paramGroups[paramGroup]["Parameters"]:
            if param["ParameterName"] == "enable_user_activity_logging" and param["ParameterValue"] == "true":
                reportString += ",Enabled," + paramGroup
                continue
            elif param["ParameterName"] == "enable_user_activity_logging" and param["ParameterValue"] == "false":
                reportString += ",Disabled," + paramGroup
                continue

        # Encryption at Rest
        if cluster["Encrypted"] == False:
            reportString += ",False"
        elif cluster["Encrypted"] == True:
            reportString += ",True"

        #encryption in transit
        for param in paramGroups[paramGroup]["Parameters"]:
            if param["ParameterName"] == "require_ssl" and param["ParameterValue"] == "true":
                reportString += ",Enabled"
                continue
            elif param["ParameterName"] == "require_ssl" and param["ParameterValue"] == "false":
                reportString += ",Disabled"
                continue

with open("redshiftAudit.csv","w") as outFile:
    outFile.write(reportString)
