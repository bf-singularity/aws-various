#!/usr/bin/python

import re
import os
import sys

if len(sys.argv) is not 2:
	print "Usage info: ....\n"
	exit(1)

awsRegions = ["us-east-1","us-east-2","us-west-1","us-west-2","ap-south-1","ap-northeast-2","ap-southeast-1","ap-southeast-2","ap-northeast-1","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-west-3","sa-east-1"]

datafile="rawAwsIpList.txt"

def formatIps():
	ips = []

	with open('rawAwsIpList.txt','rw') as inputfile:
        	for line in inputfile:
                       	if re.findall(r'[0-9]+(?:\.[0-9]+){3}', line):
				line = re.sub(r'[^\d\.]','',line)
				ips.append(line)

	with open('IPList.txt','w+') as outfile:
        	for ip in ips:
			outfile.write(ip + '\n')

try:
	with open(datafile) as f:
		print('%s exists\n' % datafile)
		formatIps()

except IOError as e:
	for region in awsRegions:
			textString = 'echo ' + str(region) + ' >> rawAwsIpList.txt'
			os.system(textString)

			textString = 'aws ec2 describe-instances --query "Reservations[*].Instances[*].PublicIpAddress" --profile ' + str(sys.argv[1]) + ' --region ' + str(region) + '>> rawAwsIpList.txt'
			print 'Querying ' + region + '...'
			os.system(textString)
			
			formatIps()

	print 'Raw IP results stored in "rawAwsIpList.txt".\nFormatted IP results stored in "IPList.txt".\n'
