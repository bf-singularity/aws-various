"""
Audit AWS S3 service for Versioning, MFA Delete, Encryption Rules, Logging Enabled, and HTTPS Enforced settings
Outputs to s3Audit.csv
"""
import boto3
import sys
import json

try:
    profile = sys.argv[1]
except:
    profile = "default"

#get Account ID
session = boto3.Session(profile_name=profile, region_name="us-east-1")
client = session.client("sts")
response = client.get_caller_identity()
account = response["Account"]

#list s3 buckets
client = session.client('s3')
response = client.list_buckets()
bucketCount = len(response["Buckets"])

bucketsNoVersioning = []
bucketsWithVersioning = []
bucketsWithErrors = []
bucketsNoMFA = []
bucketsWithMFA = []
reportString = "Account,S3 Bucket Name, Versioning, MFA Delete, Encryption Rules, Logging Enabled, HTTPS Enforced"
bucketCounter = 1
numBuckets = str(len(response["Buckets"]))
for bucket in response["Buckets"]:
    httpsEnforced = False
    print("Querying bucket " + str(bucketCounter) + "/" + numBuckets + ": " + bucket["Name"])
    try:
        details = client.get_bucket_versioning(Bucket=bucket["Name"])
    except: # this triggers if user does not have permissions to query the S3 bucket
        print("Unable to get info for bucket: " + bucket["Name"])    
        bucketsWithErrors.append(bucket["Name"])
        reportString += "\n" + account + "," + bucket["Name"] + ",UNKNOWN,UNKNOWN,UNKNOWN,UNKNOWN,UNKNOWN"
        bucketCounter += 1
        continue

    #versioning
    if not "Status" in details: #Status is not always returned. If not returned, it's not enabled
        bucketsNoVersioning.append(bucket["Name"])
        reportString += "\n" + account + "," + bucket["Name"] + ",False,"
    elif details["Status"] != "Enabled":
        bucketsNoVersioning.append(bucket["Name"])
        reportString += "\n" + account + "," + bucket["Name"] + ",False,"
    else:
        bucketsWithVersioning.append(bucket["Name"])
        reportString += "\n" + account + "," + bucket["Name"] + ",True,"

    #MFA delete
    if not "MFADelete" in details:
        bucketsNoMFA.append(bucket["Name"])
        reportString += "False"
    elif details["MFADelete"] != "Enabled":
        bucketsNoMFA.append(bucket["Name"])
        reportString += "False"
    else:
        bucketsWithMFA.append(bucket["Name"])
        reportString += "True"

    #encryption
    try:     
        encDetails = client.get_bucket_encryption(Bucket=bucket["Name"])
    except:
        encDetails = ""

    if encDetails:
        # the below comes packaged in a list, which makes me think it's possible for more than one entry to exist?
        if len(encDetails["ServerSideEncryptionConfiguration"]["Rules"]) > 1:
            counter = 1
            newRule = ","
            for rule in encDetails["ServerSideEncryptionConfiguration"]["Rules"]:
                if counter > 1:
                    newRule += " & "
                newRule += "(" + str(counter) + ") " + str(rule["ApplyServerSideEncryptionByDefault"])
                reportString += newRule
                counter += 1
        else:
            reportString += "," + str(encDetails["ServerSideEncryptionConfiguration"]["Rules"][0].replace(",",";")) #replacing comma in dict so it doesn't mess up the csv

    else:
        reportString += ",None"

    #logging
    try:
        logDetails = client.get_bucket_logging(Bucket=bucket["Name"])

    except:
        logDetails = ""

    if logDetails and "LoggingEnabled" in logDetails:
        reportString += ",True"
    else:
        reportString += ",False"

    #HTTPS Enforced
    try:
        httpsDetails = client.get_bucket_policy(Bucket=bucket["Name"])
    except:
        httpsDetails = ""

    if httpsDetails:
        r = json.loads(httpsDetails["Policy"])
        for statement in r["Statement"]:
            if "Condition" in statement:
                if statement["Effect"] == "Deny" and "Bool" in statement["Condition"] and "aws:SecureTransport" in statement["Condition"]["Bool"] and statement["Condition"]["Bool"]["aws:SecureTransport"] == "false":
                    httpsEnforced = True

    if httpsEnforced:
        reportString += ",True"
    else:
        reportString += ",False"

    bucketCounter += 1

#report
with open("s3Audit.csv", "w") as outFile:
    outFile.write(reportString)
