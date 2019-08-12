#!/usr/bin/python
import sys
import datetime
import csv

# function to print usage info
#def usage():

# function to parse input arguments
#def argParse():

# function to load csv file
def loadFile():
	file = open(sys.argv[1],'r')
	return file
	
#def unusedAccountCheck ():

def main():
	#argParse()
	
	file = loadFile()
	csvReader = csv.reader(file)
	next(csvReader, None)  # skip the headers
	
	#get current date and time
	now = datetime.datetime.now()
	
	# define arrays to hold arns for accounts in violation
	rootAPI = []
	rootMFA = []
	userMFA = []
	unusedAccounts = []
	multipleAPIKeys = []
	
	#run through the rows in the spreadsheet to pupulate violation arrays
	for row in csvReader:
		# -------------------------
		# parse relevant spreadsheet variables
		# -------------------------
		user = row[0] # user
		arn = row[1] # arn
		
		#----------was the user created more than a year ago?----------
		olderThanOneYear = 1
		oneYearAgo = datetime.datetime.now() - datetime.timedelta(days=365) #does not account for leap years
		userCreated = row[2]
		if userCreated.endswith('+00:00'):
			userCreated = userCreated[:-6]

		difference = datetime.datetime.strptime(userCreated, '%Y-%m-%dT%H:%M:%S') - oneYearAgo
		if difference.days >= 0:
			olderThanOneYear = 0

		#----------can user login to the console?----------
		if row[3].lower() == 'true': 
			consoleLogin = 1
		else: 
			consoleLogin = 0
		
		#----------when did the user last login to the console?----------
		#lastLogin= 'N/A' # define var
		#if consoleLogin == 1:
		lastLogin = row[4]
		if lastLogin == 'no_information' or lastLogin == 'N/A':
			lastLogin = '1999-12-31T23:59:59+00:00'
		if lastLogin.endswith('+00:00'):
			lastLogin = lastLogin[:-6]
		lastLogin = datetime.datetime.strptime(lastLogin, '%Y-%m-%dT%H:%M:%S')
		
		#----------is MFA enabled?----------
		if row[7].lower() == 'true':
			mfa = 1
		else:
			mfa = 0
		
		#----------is API key set 1 active?----------
		if row[8].lower() == 'false':
			key1Active = 0
		else:
			key1Active = 1

		#----------was key1 ever used?----------
		key1Used = 0 # define var
		if key1Active == 1:
			if row[10] == 'N/A':
				key1Used = 0
			else:
				key1Used = 1

		#----------when was key1 last used?----------
		key1LastUsed = 'N/A' # define var
		if key1Used == 1:
			key1LastUsed = row[10]
			if key1LastUsed.endswith('+00:00'):
				key1LastUsed = key1LastUsed[:-6]
			key1LastUsed = datetime.datetime.strptime(key1LastUsed, '%Y-%m-%dT%H:%M:%S')
		else:
			key1LastUsed = 'N/A'
		
		#----------is API key set 2 active?----------
		if row[13].lower() == 'false':
			key2Active = 0
		else:
			key2Active = 1
		
		#----------was key2 ever used?----------
		key2Used = 0 # define var
		if key2Active == 1:
			if row[15] == 'N/A':
				key2Used = 0
			else:
				key2Used = 1
				
		#----------when was the key last used?----------
		key2LastUsed = 'N/A' # define var
		if key2Used == 1:
			key2LastUsed = row[15]
			if key2LastUsed.endswith('+00:00'):
				key2LastUsed = key2LastUsed[:-6]
			key2LastUsed = datetime.datetime.strptime(key2LastUsed, '%Y-%m-%dT%H:%M:%S')
		else:
			key2LastUsed = 'N/A'
		
		# -------------------------
		# debug
		# -------------------------
		#print user
		#print consoleLogin
		#print mfa
		#print row[3]
		#print key1Used

		# -------------------------
		# run tests
		# -------------------------
		# TEST 1: does the root account have either key1 or key2 enabled? [Active API key for root account]
		if user == '<root_account>' and (key1Active == 1 or key2Active == 1):
			rootAPI.append(arn)
			
		# TEST 2: does the root account have mfa enabled? [Lack of MFA on root account]
		if user == '<root_account>' and mfa == 0:
			rootMFA.append(arn)
			
		# TEST3: if the user has a password enabled, does it also have mfa enabled? [Lack of MFA on user accounts]
		if user != '<root_account>' and consoleLogin == 1 and mfa == 0:
			userMFA.append(arn)
		
		# TEST 4: has the account been used in the last 12 months?
		userHasLoggedIn = 0 # define var
		userHasUsedKey1 = 0 # define var
		userHasUsedKey2 = 0 # define var
		
		# check if the user has logged in in the last year. If they have, var=1
		#if consoleLogin == 1:
		if lastLogin >= (now - datetime.timedelta(days=365)):
			userHasLoggedIn = 1
		# if the user does not have console access, check if API key1 is active and has been used in the last year. If it has been used, var=1
		if key1Active == 1 and key1Used == 1:
			if key1LastUsed >= (now - datetime.timedelta(days=365)):
				userHasUsedKey1 = 1
		# if the user does not have console access, check if API key2 is active and has been used in the last year. If it has been used, var=1
		if key2Active == 1 and key2Used == 1:
			if key2LastUsed >= (now - datetime.timedelta(days=365)):
				userHasUsedKey2 = 1
		
		# if the user has been inactivated, then do nothing. 
		if consoleLogin == 0 and key1Active == 0 and key2Active == 0:
			pass

		# if the user is active, is not the root account, was created more than a year ago, and has not logged in or used key1 or key2 in the last year, write them up
		if user != '<root_account>' and olderThanOneYear == 1 and userHasLoggedIn == 0 and userHasUsedKey1 == 0 and userHasUsedKey2 == 0:
			unusedAccounts.append(arn)
		
		# TEST 5: are both key1 and key2 enabled? [Accounts with multiple access keys]
		if key1Active == 1 and key2Active == 1:
			multipleAPIKeys.append(arn)
	
	# for each array, print out the ARNs of offending accounts
	with open('iamFindings.txt', 'w+') as outfile:
		outfile.write('Findings:\n\n')
		
		outfile.write('Root account has one or more API keys enabled.\n')
		if rootAPI:
			for i in rootAPI:
				outfile.write(i)
				outfile.write('\n')
		else:
			outfile.write('None\n')
		
		outfile.write('\nRoot account is not protected with MFA.\n')
		if rootMFA:
			outfile.write(rootMFA[0])
			outfile.write('\n')
		else:
			outfile.write('None\n')
		
		outfile.write('\nThe following user accounts are not protected with MFA.\n')
		if userMFA:
			for account in userMFA:
				outfile.write(account)
				outfile.write('\n')
			outfile.write('\n')
		else:
			outfile.write('None\n')
	
		outfile.write('\nThe following accounts are active but have not been used in the last year.\n')
		if unusedAccounts:
			for account in unusedAccounts:
				outfile.write(account)
				outfile.write('\n')
			outfile.write('\n')
		else: 
			outfile.write('None\n')
		
		outfile.write('\nThe following accounts have both sets of API keys enabled.\n')
		if multipleAPIKeys:
			for account in multipleAPIKeys:
				outfile.write(account)
				outfile.write('\n')
			outfile.write('\n')
		else:
			outfile.write('None\n')

print 'Results written to "iamFindings.txt"\nMake sure to double check the results for accuracy! People make mistakes when writing scripts.\n'

if __name__ == "__main__":
    main()
