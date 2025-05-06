import json
import boto3
import logging
import time
import requests
from datetime import datetime, timedelta

# Initialize the AWS clients
waf_client = boto3.client('wafv2')
alb_client = boto3.client('elbv2')
ddb_client = boto3.client('dynamodb')

# WAF Web ACL configuration
web_acl_name = ''# your web acl name
web_acl_id = '' #your web acl (AWS web application firewall) id
scope = 'REGIONAL'
ip_set_id = '' #your IP set id
ip_set_name = '' # your IPset name
ip_set_scope = 'REGIONAL'

# DynamoDB table name and block duration
ddb_table_name = 'BlockedIPs'
block_duration_minutes = 60

# ALB Load Balancer and Target Group ARNs
alb_arn = ''#arn of your application load balancer
target_group_arn = ''#arn of your target group in which your ec2 is present

# JSON data source hosted on EC2
ec2_json_url = ''#your ec2 json public url

# Logger setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger()

def lambda_handler(event, context):
    logger.info("Starting JSON fetch and analysis from EC2-hosted URL...")

    try:
        response = requests.get(ec2_json_url)
        response.raise_for_status()
        json_data = response.json()
        logger.info("Successfully fetched JSON from EC2.")
    except Exception as e:
        logger.error(f"Error retrieving JSON from EC2: {e}")
        return {'statusCode': 500, 'body': 'Error fetching JSON from EC2'}

    if not json_data:
        logger.warning("Empty or invalid JSON content.")
        return {'statusCode': 400, 'body': 'Invalid or empty JSON'}

    for flow in json_data:
        flow_id = flow.get('FlowID')
        prediction = flow.get('Prediction')
        source_ip = flow.get('source_ip')

        if prediction == 'DDOS' and source_ip:
            logger.info(f"DDOS detected for FlowID: {flow_id}, blocking IP: {source_ip}...")
            block_ip(source_ip)
        elif prediction == 'BENIGN':
            logger.info(f"Benign traffic detected for FlowID: {flow_id}, redirecting traffic to Instance A...")
            redirect_traffic_to_instance_a()

    return {
        'statusCode': 200,
        'body': 'Script executed successfully'
    }

def block_ip(ip):
    ip = f"{ip}/32"
    ttl = int(time.time()) + block_duration_minutes * 60

    try:
        ip_set = waf_client.get_ip_set(
            Name=ip_set_name,
            Scope=ip_set_scope,
            Id=ip_set_id
        )
        addresses = ip_set['IPSet']['Addresses']

        if ip not in addresses:
            addresses.append(ip)

            waf_client.update_ip_set(
                Name=ip_set_name,
                Scope=ip_set_scope,
                Id=ip_set_id,
                LockToken=ip_set['LockToken'],
                Addresses=addresses
            )

            ddb_client.put_item(
                TableName=ddb_table_name,
                Item={
                    'ip': {'S': ip},
                    'ttl': {'N': str(ttl)}
                }
            )

            logger.info(f"Blocked IP {ip} for {block_duration_minutes} minutes.")
        else:
            logger.info(f"IP {ip} is already blocked.")
    except Exception as e:
        logger.error(f"Error blocking IP {ip}: {e}")

def redirect_traffic_to_instance_a():
    try:
        response = alb_client.describe_listeners(LoadBalancerArn=alb_arn)
        listeners = response['Listeners']
        logger.info(f"Found {len(listeners)} listeners for ALB {alb_arn}")

        for listener in listeners:
            listener_arn = listener['ListenerArn']
            logger.info(f"Attempting to modify listener: {listener_arn}")
            alb_client.modify_listener(
                ListenerArn=listener_arn,
                DefaultActions=[
                    {
                        'Type': 'forward',
                        'TargetGroupArn': target_group_arn
                    }
                ]
            )
            logger.info(f"Successfully redirected traffic for listener {listener_arn} to Instance A.")
    except alb_client.exceptions.ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        logger.error(f"ClientError redirecting traffic to Instance A: {error_code} - {error_message}")
        raise
    except Exception as e:
        logger.error(f"Unexpected error redirecting traffic to Instance A: {str(e)}")
        raise