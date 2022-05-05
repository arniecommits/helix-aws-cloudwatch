from __future__ import print_function
import json
import boto3
import base64
import os,logging
import requests
from botocore.exceptions import ClientError
print('Loading function')

def get_secret():
    logging.info("Extracting API Keys from store")
    secret_name = os.environ["secret_name"]
    region_name = os.environ["aws_region"]

    # Create a Secrets Manager client
    session = boto3.session.Session()
    client = session.client(
        service_name='secretsmanager',
        region_name=region_name
    )

    try:
        get_secret_value_response = client.get_secret_value(
            SecretId=secret_name
        )
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'DecryptionFailureException':
            raise e
        elif e.response['Error']['Code'] == 'InternalServiceErrorException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidParameterException':
            raise e
        elif e.response['Error']['Code'] == 'InvalidRequestException':
            raise e
        elif e.response['Error']['Code'] == 'ResourceNotFoundException':
            raise e
    else:
        
        if 'SecretString' in get_secret_value_response:
            secret = get_secret_value_response['SecretString']
            secret = json.loads(secret)
            return secret
    

def lambda_handler(event, context):
    print(json.dumps(event))
    message = event['Records'][0]['Sns']['Message']
    print (message)
    secret=get_secret()
    api_key=secret["Helix-Key"]
    url=os.environ["helix_url"]
    headers = { 
        'Authorization':api_key, 
        'Content-Type':'application/vnd.api+json'
    }
    
    ec2 = boto3.resource('ec2')
    message = message.replace("'", "\"")
    message=json.loads(message)
    instanceid=""
    try:
        instanceid=message["Trigger"]["Dimensions"][0]["value"]
    except:
        instanceid=message["Trigger"]["Metrics"][0]["MetricStat"]["Metric"]["Dimensions"][0]["value"]
    print (instanceid)
    instance = ec2.Instance(instanceid)
    message["public_ip_address"]=instance.public_ip_address
    message["private_ip_address"]=instance.private_ip_address
    message["InstanceId"]=instanceid
    logging.info(message)
    response = requests.post(url,headers=headers,json=message)
    return response.status_code
