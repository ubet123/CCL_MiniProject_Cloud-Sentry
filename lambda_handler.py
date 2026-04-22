import boto3
import os
import hashlib
import json
import urllib.request
import urllib.error
import time

s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')
sns = boto3.client('sns')

def lambda_handler(event, context):
    bucket_name = event['Records'][0]['s3']['bucket']['name']
    file_key = event['Records'][0]['s3']['object']['key']
    
    local_path = f"/tmp/{file_key}"
    clean_bucket = os.environ['CLEAN_BUCKET']
    quarantine_bucket = os.environ['QUARANTINE_BUCKET']
    vt_api_key = os.environ['VT_API_KEY']
    sns_arn = os.environ['SNS_TOPIC_ARN']
    
    s3.download_file(bucket_name, file_key, local_path)
    
    sha256_hash = hashlib.sha256()
    with open(local_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    file_hash = sha256_hash.hexdigest()

    # --- VirusTotal Check using built-in urllib ---
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": vt_api_key}
    
    status = "Clean"
    target_bucket = clean_bucket
    
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req) as response:
            result = json.loads(response.read().decode())
            stats = result['data']['attributes']['last_analysis_stats']
            if stats.get('malicious', 0) > 0:
                status = "Infected"
                target_bucket = quarantine_bucket
    except urllib.error.HTTPError as e:
        if e.code == 404:
            status = "Unknown/Safe"
        else:
            print(f"VT API Error: {e.code}")
    except Exception as e:
        print(f"General Error: {str(e)}")

    # Move file
    s3.copy_object(Bucket=target_bucket, CopySource={'Bucket': bucket_name, 'Key': file_key}, Key=file_key)
    s3.delete_object(Bucket=bucket_name, Key=file_key)
    
    # Log to DynamoDB
    table = dynamodb.Table('ScanLogs')
    table.put_item(Item={
        'File_Name': file_key,
        'Timestamp': int(time.time()),
        'Status': status,
        'Hash': file_hash
    })

    if status == "Infected":
        sns.publish(TopicArn=sns_arn, Message=f"Malware Alert: {file_key} is infected!", Subject="Cloud-Sentry Alert")
    
    return {"status": status, "file": file_key}
