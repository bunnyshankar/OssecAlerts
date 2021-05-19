#!/bin/bash

region="" #update aws region
account_id="" #AWS account id
lambda_arn="" #Update Lambda ARN printed from earlier script createLambda.sh
lambda_function_name="" #update Lambda function name printed from earlier script createLambda.sh

function addSubFilter() {
loggroup_arn=$1
loggroup_name=$2
statement_id=$3
aws lambda add-permission --function-name "${lambda_function_name}" --statement-id ${statement_id} --principal "logs.$region.amazonaws.com" --action "lambda:InvokeFunction" --source-arn "${loggroup_arn}:*" --source-account "${account_id}"
aws logs put-subscription-filter --log-group-name ${loggroup_name}  --filter-name ossec    --filter-pattern ""  --destination-arn ${lambda_arn}
}

addSubFilter "" ""  "" #The First Parameter is the arn of your loggroup and the second parameter is loggroup name and the third parameter is for statement id for lambda.

