''' Ossec Log analyzer  '''
import base64
import gzip
import ast
import json
import os
import boto3

SNS = boto3.client('sns')

def handler(event, context):
    ''' Ossec CW Lambda Handler '''
    enc_msg = event['awslogs']['data']
    dec_msg = base64.b64decode(enc_msg)
    dcmp_msg = (gzip.decompress(dec_msg)).decode("UTF-8")
    data = ast.literal_eval(dcmp_msg)

    host = data['logStream']
    msg1 = None
    for logevents in data['logEvents']:
        msg = logevents['message']
        if "Alert" in msg and msg1:
            SNS.publish(
                TargetArn=os.environ['SNS_TOPIC'],
                Subject='Intrusion Alerts New',
                Message=json.dumps({
                    'default': 'Intrusion Detection on  this host {}  and the alert is {} '.format(
                        host, msg1)
                }),
                MessageStructure='json'
            )
            msg1 = None
        if msg1:
            msg1 = msg1 + msg + '\n'
        if "level 5" in msg or "level 10" in msg or "level 11" in msg or "level 12" in msg or "level 13" in msg or "level 14" in msg or "level 15" in msg:
            #if level in msg:
            msg1 = msg + '\n'
            print(msg)
