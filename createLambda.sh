#!/bin/bash

### This function has to be executed once per Account as this satisfies ossec log analysic ###

sns_arn="" #make sure SNS is created before executing this script. Update sns_arn here.
lambda_role_name="" #Give name to the role ex: ossec-lambda-role
lambda_function_name="" #give name to your Lambda Function like ossec_log_analysis

sed  "s/SNSARN/${sns_arn}/" snstemplate.json > sns.json
aws iam create-role --role-name ${lambda_role_name} --assume-role-policy-document file://trust-policy.json  > a.txt
role_arn=`grep arn a.txt | awk '{split($2,a,"\""); print a[2]}'`
aws iam attach-role-policy --role-name ${lambda_role_name} --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam put-role-policy --role-name ${lambda_role_name} --policy-name sns --policy-document file://sns.json
sleep 10
aws lambda create-function --function-name ${lambda_function_name} --zip-file fileb://ossec.zip --role ${role_arn} --handler ossec.handler --runtime python3.8 --environment Variables={SNS_TOPIC="${sns_arn}"} > lambda.log
lambda_arn=`grep FunctionArn lambda.log | awk '{split($2,a,"\""); print a[2]}'`
echo "Lambda ARN is $lambda_arn and Lambda Function name is $lambda_function_name"
