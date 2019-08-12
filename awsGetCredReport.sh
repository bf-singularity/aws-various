#!/bin/bash

if [ "$#" -ne 1 ]; then
	echo "Please provide the name of the aws profile to use."
	exit
fi

echo "Getting Credential Report."
aws iam get-credential-report --profile $1 | grep Content | cut -d '"' -f 4 | base64 -d > credential_report_$1.csv
echo "Done!"
