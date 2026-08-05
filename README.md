# S3 Guard — Automated Public Bucket Detector & Remediator

An automated, serverless cloud security pipeline built on AWS to detect public S3 bucket exposures in real time and automatically enforce Block Public Access policies.

## Architecture

```text
+---------------------+
|   AWS EventBridge   |  <-- Triggers every 15 mins (Schedule Rule)
+----------+----------+
           |
           v
+---------------------+
|     AWS Lambda      |  <-- Runs Python (boto3) script to scan S3 buckets
+----+-----------+----+
     |           |
     |           +-----------------------+
     v                                   v
+--------------------+         +--------------------+
|   AWS S3 Bucket    |         |      AWS CloudWatch|
| (Applies Public    |         | (Logs execution &  |
|  Access Block)     |         |  audit details)    |
+---------+----------+         +--------------------+
          |
          v
+--------------------+
|      AWS SNS       |  <-- Sends email alert to SOC / DevSecOps
+--------------------+
```

## Key Features
* Scans all S3 buckets within an AWS account on a defined schedule.
* Automatically applies AWS S3 `Block Public Access` configurations upon detecting public permissions.
* Dispatches instant SNS email notifications to SOC/DevSecOps teams with bucket details.
* Logs all remediation events for compliance and security auditing.

## Tech Stack
* AWS Lambda, EventBridge, S3, SNS, CloudWatch, IAM
* Python (`boto3` SDK)
* JSON IAM Policies
