import json
import logging
import boto3
from botocore.exceptions import ClientError

logger = logging.getLogger()
logger.setLevel(logging.INFO)

s3_client = boto3.client('s3')
sns_client = boto3.client('sns')

SNS_TOPIC_ARN = "arn:aws:sns:us-east-1:111122223333:S3GuardAlerts"

def lambda_handler(event, context):
    logger.info("Starting S3 Guard public bucket scan...")
    
    try:
        response = s3_client.list_buckets()
        buckets = response.get('Buckets', [])
        remediated_buckets = []

        for bucket in buckets:
            bucket_name = bucket['Name']
            is_public = False
            
            try:
                pab = s3_client.get_public_access_block(Bucket=bucket_name)
                config = pab['PublicAccessBlockConfiguration']
                
                if not (config.get('BlockPublicAcls') and 
                        config.get('IgnorePublicAcls') and 
                        config.get('BlockPublicPolicy') and 
                        config.get('RestrictPublicBuckets')):
                    is_public = True
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlock':
                    is_public = True
                else:
                    logger.error(f"Error checking {bucket_name}: {str(e)}")
                    continue

            if is_public:
                logger.warning(f"Public exposure detected on bucket: {bucket_name}. Enforcing Block Public Access...")
                s3_client.put_public_access_block(
                    Bucket=bucket_name,
                    PublicAccessBlockConfiguration={
                        'BlockPublicAcls': True,
                        'IgnorePublicAcls': True,
                        'BlockPublicPolicy': True,
                        'RestrictPublicBuckets': True
                    }
                )
                remediated_buckets.append(bucket_name)

        if remediated_buckets:
            message = (
                f"ALERT: S3 Guard remediated public access on the following bucket(s):\n\n"
                + "\n".join([f"- {name}" for name in remediated_buckets]) +
                "\n\nActions Taken: Enforced Block Public Access."
            )
            sns_client.publish(
                TopicArn=SNS_TOPIC_ARN,
                Subject="[S3 Guard] Automated Remediation Triggered",
                Message=message
            )

        return {
            'statusCode': 200,
            'body': json.dumps({
                'message': 'Scan completed successfully',
                'remediated_buckets': remediated_buckets
            })
        }

    except Exception as e:
        logger.error(f"Execution error: {str(e)}")
        raise e
