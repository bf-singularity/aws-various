import boto3
import botocore
import json
import ipaddress
import requests
import argparse

"""
This script runs through security groups and checks to see if they contain IP addresses in the ingress or egress list that belong to a specified country
usage country.py [-h] {country} {profile}
"""
def isCountryIp(ip,countryIpList):
    try:
        address = ipaddress.ip_network(ip)
    except:
        print("!!!! " + ip + " is not an IP address !!!!")
    if any(address.overlaps(r) for r in countryIpList):
        return True
    return False

#parse arguments
parser = argparse.ArgumentParser()
parser.add_argument("countrycode", help="The two letter code for the country that you want to compare the security groups' CIDR definitions against")
parser.add_argument("profile", help="The AWS profile to run against in order to obtain a list of security groups")
parser.add_argument("-r", "--region", help="The AWS region to run against. Entering this here will override the default region in the AWS config file")
args = parser.parse_args()

country = args.countrycode.upper()
countryList = ("AD","AE","AF","AG","AI","AL","AM","AO","AR","AS","AT","AU","AW","AX","AZ","BA","BB","BD","BE","BF","BG","BH","BI","BJ","BL","BM","BN","BO","BQ","BR","BS","BT","BW","BY","BZ","CA","CD","CF","CG","CH","CI","CK","CL","CM","CN","CO","CR","CU","CV","CW","CY","CZ","DE","DJ","DK","DM","DO","DZ","EC","EE","EG","ER","ES","ET","FI","FJ","FK","FM","FO","FR","GA","GB","GD","GE","GF","GG","GH","GI","GL","GM","GN","GP","GQ","GR","GT","GU","GW","GY","HK","HN","HR","HT","HU","ID","IE","IL","IM","IN","IO","IQ","IR","IS","IT","JE","JM","JO","JP","KE","KG","KH","KI","KM","KN","KP","KR","KW","KY","KZ","LA","LB","LC","LI","LK","LR","LS","LT","LU","LV","LY","MA","MC","MD","ME","MF","MG","MH","MK","ML","MM","MN","MO","MP","MQ","MR","MS","MT","MU","MV","MW","MX","MY","MZ","NA","NC","NE","NF","NG","NI","NL","NO","NP","NR","NU","NZ","OM","PA","PE","PF","PG","PH","PK","PL","PM","PR","PS","PT","PW","PY","QA","RE","RO","RS","RU","RW","SA","SB","SC","SD","SE","SG","SI","SK","SL","SM","SN","SO","SR","SS","ST","SV","SX","SY","SZ","TC","TD","TG","TH","TJ","TK","TL","TM","TN","TO","TR","TT","TV","TW","TZ","UA","UG","US","UY","UZ","VA","VC","VE","VG","VI","VN","VU","WF","WS","YE","YT","ZA","ZM","ZW")
if country not in countryList:
    print(country + " is not a valid country code")
    exit(0)

try:
    session = boto3.Session(profile_name=args.profile)
except:
    print("\"" + args.profile + "\" is not defined in the AWS config file. Did you run \"aws configure --profile " + args.profile + "\"?")
    exit(0)

try:
    if args.region:
        client = session.client("ec2", region_name=args.region)
    else:
        client = session.client("ec2")
except botocore.exceptions.NoRegionError:
    print("No AWS region was specified on the command line or in the AWS config file. Exiting.")
    exit(0)

print("Getting security groups from AWS")
security_groups = client.describe_security_groups()

"""
#write results so I can review the format
with open("outfile.json", "w") as outfile:
    outfile.write(json.dumps(security_groups)) 
"""

#create list of ipv4 CIDRs beloning to country
print("Getting list of IPv4 CIDRs belonging to " + country)
url = "http://ipverse.net/ipblocks/data/countries/"+country.lower()+".zone"
r = requests.get(url)
countryIpv4List = []
for cidr in r.text.splitlines():
    if not cidr.startswith("#"):
        countryIpv4List.append(ipaddress.ip_network(cidr, False))

#create list of ipv6 CIDRs beloning to country
print("Getting list of IPv6 CIDRs belonging to " + country)
url = "http://ipverse.net/ipblocks/data/countries/"+country.lower()+"-ipv6.zone"
r = requests.get(url)
countryIpv6List = []
for cidr in r.text.splitlines():
    if not cidr.startswith("#"):
        countryIpv6List.append(ipaddress.ip_network(cidr, False))

#TODO add in functionality to deal with IPv6
resultsList = []
i = 1
for sg in security_groups["SecurityGroups"]:
    print("Parsing Security Group " + str(i) + "/" + str(len(security_groups["SecurityGroups"])) + ": " + sg["GroupName"]) 
    if sg["IpPermissions"]:
        #extract IP addresses for ingress
        for details in sg["IpPermissions"]:
            if details["IpRanges"]:
                #do stuff if IpRanges exists
                for ipRange in details["IpRanges"]:
                    resultsDict = {}
                    if ipRange["CidrIp"] == "0.0.0.0/0":
                        continue #publicly accessible, not specific to country
                    elif isCountryIp(ipRange["CidrIp"], countryIpv4List) == True:
                        resultsDict["sg"] = sg["GroupName"]
                        resultsDict["type"] = "ingress"
                        resultsDict["cidr"] = ipRange["CidrIp"]
                        if not "ToPort" in details:
                            resultsDict["port"] = "all ports"
                        else:
                            resultsDict["port"] = "port " + str(details["ToPort"])
                        resultsList.append(resultsDict)
            if details["Ipv6Ranges"]:
                #do stuff if Ipv6Ranges exists
                #print(sg["GroupName"] + " contains IPV6 addresses.")
                #exit(0)
                for ipRange in details["Ipv6Ranges"]:
                    if ipRange["CidrIpv6"] == "::/0":
                        continue #publicly accessible, not specific to country
                    else: #this was not reached when running script, so no need to define anything specific here
                        print(sg["GroupName"] + " needs your attention")
                        exit(0)
    if sg["IpPermissionsEgress"]:
        #extract IP addresses for egress
        for details in sg["IpPermissionsEgress"]:
            if details["IpRanges"]:
                #do stuff if IpRanges exists
                for ipRange in details["IpRanges"]:
                    resultsDict = {}
                    if ipRange["CidrIp"] == "0.0.0.0/0":
                        continue #publicly accessible, not specific to country
                    elif isCountryIp(ipRange["CidrIp"], countryIpv4List) == True:
                        resultsDict["sg"] = sg["GroupName"]
                        resultsDict["type"] = "egress"
                        resultsDict["cidr"] = ipRange["CidrIp"]
                        if not "FromPort" in details:
                            resultsDict["port"] = "all ports"
                        else:
                            resultsDict["port"] = "port " + str(details["FromPort"])
                        resultsList.append(resultsDict)
            if details["Ipv6Ranges"]: #this was not reached when running script, so no need to define anything specific here
                #do stuff if Ipv6Ranges exists
                print(sg["GroupName"] + " contains IPV6 addresses in egress.")
                exit(0)
    i += 1

#print results
print("")
if not resultsList:
    print("No security groups found that define IP CIDRs from the country you specified")

for result in resultsList:
    if result["type"] == "ingress":
        print("Security group \"" + result["sg"] + "\" allows " + result["type"] + " connections on " + result["port"] + " from " + result["cidr"] + ", which is CIDR belonging to " + country + ".")
    else:
        print("Security group \"" + result["sg"] + "\" allows " + result["type"] + " connections from " + result["port"] + " to " + result["cidr"] + ", which is CIDR belonging to " + country + ".")