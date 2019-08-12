#!/usr/bin/python
#v1.0
#10/27/2017
#parse out the EC2 security groups that permit access to ports to 0.0.0.0/0
#requires the Scout2 config.js file. EG, after running scout2 on [client] it will generate a file: scout2-report\inc-awsconfig\aws_config-[client].js
#usage: python parse_securitygroups.py aws_config-[client].js

import sys
import simplejson
import re
import os

if len(sys.argv) is not 2:
	print "Please specify the location of the scoutsuite scoutsuite_results-aws-<profile>.js file.\nThis file is usually found in \"scoutsuite-report/scoutsuite-results\"\n"
	exit(0)
else:
	jsonFile = sys.argv[1]
	
print "Parsing JSON file and saving output to 'sgFindings.csv'\n"

#if os.path.isfile(scout2-report/inc-awsconfig/aws_config-*.js:
#	print 'works'

#open json file from scout-2
with open(jsonFile) as data:
	contents = data.read()
	contents = contents.replace('\n','') #remove line breaks
	contents = contents.replace('scoutsuite_results =', '') #remove the text at the beginnging of the json file

json = simplejson.loads(contents)

#create array of regions and populate
regions = []
for key,value in enumerate(json["services"]["ec2"]["regions"]):
	regions.append(value)

#create array of externally accessible instances
#externally_accessible_instances = []	
	
#counter declarations
r = 0 #counter to enumerate through regions
a = 0 #counter to enumerate through vpcs 
b = 0 #counter to enumerate through security groups
c = 0 #counter to enumerate through protocols
d = 0 #counter to enumerate through ports

#commented out code can be used for testing 
#for x,y in enumerate(json["services"]["ec2"]["regions"][regions[r]]["vpcs"]["vpc-c23edda6"]["security_groups"]["sg-ef692694"]["name"]): #["rules"]["ingress"]["protocols"]["TCP"]["ports"]["9000"]["cidrs"]):
#	print y
#exit(1)	

#open output file
with open('sgFindings.csv', 'w+') as csv:

	#write file headers
	csv.write("Region,VPC ID,Security Group ID,Security Group Name,Protocol,Port,Open To,In Use\n ")
	#print vpcs
	
	#loop through the regions
	while r < len(regions):
		a = 0 #reset security group counter for each vpc
		
		#create array of VPCs and populate
		vpcs = []
		for key,value in enumerate(json["services"]["ec2"]["regions"][regions[r]]["vpcs"]):
			vpcs.append(value)
			
		while a < len(vpcs):
			b = 0 #reset security group counter for each vpc
			
			#create array for security groups in vpc and populate
			sgs = []
			for key,value in enumerate(json["services"]["ec2"]["regions"][regions[r]]["vpcs"][vpcs[a]]["security_groups"]):
				sgs.append(value)
			#for each vpc, loop through security groups
			while b < len(sgs):
				
				#commented out code can be used to test for specific security group
				#if vpcs[a] != "vpc-38d80941":
				#	a += 1
				#	break
				
				c = 0 #reset protocol counter for each security group
				in_use = "No" #set variable for whether security group is in use to No by default
				#externally_accessible = "No"
				
				#see if security group is in use
				for key,value in enumerate(json["services"]["ec2"]["regions"][regions[r]]["vpcs"][vpcs[a]]["security_groups"][sgs[b]]):
					if value == "used_by":
						in_use = "Yes"
				
				#store security group name
				name = json["services"]["ec2"]["regions"][regions[r]]["vpcs"][vpcs[a]]["security_groups"][sgs[b]]["name"]

				#if the security group ingress rule count in 0, skip to the next security group
				if json["services"]["ec2"]["regions"][regions[r]]["vpcs"][vpcs[a]]["security_groups"][sgs[b]]["rules"]["ingress"]["count"] == 0:
					#print "security group with empty ingress rules"
					b += 1
				
				else:
				
					#create array for protocols and populate
					proto = [] 
					for k,v in enumerate(json["services"]["ec2"]["regions"][regions[r]]["vpcs"][vpcs[a]]["security_groups"][sgs[b]]["rules"]["ingress"]["protocols"]):
						proto.append(v)
					
					#for each security group, enumerate through protocols
					while c < len(proto):
						d = 0 #reset port counter for each protocol
						
						#if the protocol is ICMP, skip it because we don't really care
						if proto[c] == "ICMP":
							c += 1
						
						else:
							
							#create array for ports and populate
							ports = []
							for x,y in enumerate(json["services"]["ec2"]["regions"][regions[r]]["vpcs"][vpcs[a]]["security_groups"][sgs[b]]["rules"]["ingress"]["protocols"][proto[c]]["ports"]):
								ports.append(y)
							
							#for each port, enumerate through source security groups / cidrs
							while d < len(ports):
								
								#commented the below section so as not to skip these ports - we probably want to report on them anyway. 
								#we don't care about port 80,443,and 1194 because generally those are meant to be open to everyone
								#if ports[d] == "80" or ports[d] == "443" or ports[d] == "1194":
								#	d += 1
								
								#else:
								#determine if the source is a security group or a CIDR
								for o,p in enumerate(json["services"]["ec2"]["regions"][regions[r]]["vpcs"][vpcs[a]]["security_groups"][sgs[b]]["rules"]["ingress"]["protocols"][proto[c]]["ports"][ports[d]]):
									if p == "security_groups":
										
										#if the ingress rule allows ALL traffic within a security group, output it to the results. Otherwise, no action currently 
										if proto[c] == "ALL":
										
											#store source security group in source_sg variable, then write to CSV file
											source_sg = str(json["services"]["ec2"]["regions"][regions[r]]["vpcs"][vpcs[a]]["security_groups"][sgs[b]]["rules"]["ingress"]["protocols"][proto[c]]["ports"][ports[d]]["security_groups"][0]["GroupId"])
											write_string =  str(regions[r]) + "," + str(vpcs[a])+","+str(sgs[b])+","+str(name)+","+str(proto[c])+","+str(ports[d])+","+source_sg + "," + in_use +"\n"
											csv.write(write_string)
											
									elif p == "cidrs":
										
										#output cidrs to variable and then use regex to extract the CIDRs without additional text or symbols
										cidr = str(json["services"]["ec2"]["regions"][regions[r]]["vpcs"][vpcs[a]]["security_groups"][sgs[b]]["rules"]["ingress"]["protocols"][proto[c]]["ports"][ports[d]]["cidrs"])
										cidr = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d+',cidr)
										
										#We only care about the ingress rule if it allows 0.0.0.0/0
										if "0.0.0.0/0" in cidr:
										
											#append all CIDRS into one string separated by semi-colon, then output to results
											cidr = ";".join(str(itm) for itm in cidr)
											write_string = str(regions[r]) + "," + str(vpcs[a])+","+str(sgs[b])+","+str(name)+","+str(proto[c])+","+str(ports[d])+","+str(cidr)+ "," + in_use +"\n"
											csv.write(write_string)
									
									#catch-all
									else: 
										print "IF this outputs to the screen then something is wrong!!!"
								
								#increase all counters
								d += 1
							c +=1
					b += 1
			a += 1
		r += 1
#end
