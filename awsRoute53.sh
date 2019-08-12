#!/bin/bash

echo "Exporting Route53 Information..."
echo '' > route53Export.txt
cli53 list --profile $1 | grep -iEo "[^ ]+\. +[0-9]+" | cut -d ' ' -f 1 | while read line;do echo [+]\ Domain\ Name:\ ${line};echo --------------------------------------------------Domain\ Name:\ ${line}-------------------------------------------------- >> route53Export.txt;cli53 export --profile $1 --full ${line} >> route53Export.txt;done
echo "Done!"
