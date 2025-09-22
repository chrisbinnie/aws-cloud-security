---
layout: default
title: "AWS Cloud Security Guide by Chris Binnie"
description: "AWS cloud security information from my working notes; covering IAM hardening, VPC security, compliance frameworks, and threat protection. Essential practices for securing AWS infrastructure against cyber threats."
keywords: "AWS security, cloud security, IAM hardening, VPC security, AWS WAF, GuardDuty, CloudTrail, compliance, threat protection, cybersecurity"
author: "Chris Binnie"
date: 2025-09-09
last_modified_at: 2025-09-09
canonical_url: "https://chrisbinnie.github.io/aws-cloud-security"
og_title: "AWS Cloud Security Guide: Complete Hardening & Protection Manual 2025"
og_description: "Secure your AWS infrastructure with this comprehensive security guide. Learn essential hardening techniques including IAM policies, VPC configuration, and advanced threat protection."
og_type: "article"
twitter_card: "summary_large_image"
schema_type: "TechnicalArticle"
---

# Chris Binnie - AWS Cloud Security: Hardening & Protection

Secure your AWS infrastructure with this security information from my working notes. Treat the following code snippets as completely untested though. This page covers essential hardening techniques from industry best practices including identity management, network security, and defense strategies for production workloads, from basic setup to advanced threat protection across all AWS services.

AWS cloud security is fundamental for protecting your infrastructure from cyber threats, data breaches, and unauthorised access. This comprehensive guide covers essential security practices, from basic IAM hardening to advanced threat protection, ensuring your AWS environment remains secure and compliant with industry standards.

Whether you're managing EC2 instances, Lambda functions, S3 buckets, or complete multi-tier architectures, these security principles apply across all AWS services and will help you build a robust defence against modern cyber threats.

## Identity and Access Management (IAM) Hardening

The foundation of AWS security begins with proper IAM configuration. Never use root account credentials for daily operations:

```bash
# Create IAM user with programmatic access
aws iam create-user --user-name admin-user

# Attach administrative policy (restrict as needed)
aws iam attach-user-policy --user-name admin-user --policy-arn arn:aws:iam::aws:policy/PowerUserAccess

# Create access keys
aws iam create-access-key --user-name admin-user

# Enable MFA for console access
aws iam create-virtual-mfa-device --virtual-mfa-device-name admin-user-mfa --path /
```

Implement least privilege access with custom IAM policies:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeInstances",
        "ec2:StartInstances",
        "ec2:StopInstances"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "ec2:ResourceTag/Environment": "Production"
        }
      }
    }
  ]
}
```

### Multi-Factor Authentication (MFA) Enforcement

Enforce MFA for all IAM users accessing the AWS console:

```bash
# Create MFA enforcement policy
aws iam create-policy --policy-name EnforceMFAPolicy --policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}'

# Attach to all users or groups
aws iam attach-user-policy --user-name username --policy-arn arn:aws:iam::ACCOUNT:policy/EnforceMFAPolicy
```

### IAM Role-Based Access Control

Use IAM roles for EC2 instances instead of embedding credentials:

```bash
# Create EC2 service role
aws iam create-role --role-name EC2-S3-Access --assume-role-policy-document '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}'

# Create instance profile
aws iam create-instance-profile --instance-profile-name EC2-S3-Profile

# Add role to instance profile
aws iam add-role-to-instance-profile --instance-profile-name EC2-S3-Profile --role-name EC2-S3-Access

# Launch EC2 with IAM role
aws ec2 run-instances --image-id ami-12345678 --instance-type t3.micro --iam-instance-profile Name=EC2-S3-Profile
```

## Network Security and VPC Configuration

### VPC Security Best Practices

Create a secure VPC with proper network segmentation:

```bash
# Create VPC with DNS support
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --enable-dns-hostnames --enable-dns-support

# Create public subnet for web tier
aws ec2 create-subnet --vpc-id vpc-12345678 --cidr-block 10.0.1.0/24 --availability-zone us-west-2a

# Create private subnet for application tier
aws ec2 create-subnet --vpc-id vpc-12345678 --cidr-block 10.0.2.0/24 --availability-zone us-west-2a

# Create private subnet for database tier
aws ec2 create-subnet --vpc-id vpc-12345678 --cidr-block 10.0.3.0/24 --availability-zone us-west-2a
```

### Security Group Configuration

Implement restrictive security groups following the principle of least privilege:

```bash
# Create web tier security group
aws ec2 create-security-group --group-name web-tier-sg --description "Web tier security group" --vpc-id vpc-12345678

# Allow HTTP/HTTPS from internet
aws ec2 authorize-security-group-ingress --group-id sg-web12345 --protocol tcp --port 80 --cidr 0.0.0.0/0
aws ec2 authorize-security-group-ingress --group-id sg-web12345 --protocol tcp --port 443 --cidr 0.0.0.0/0

# Create application tier security group
aws ec2 create-security-group --group-name app-tier-sg --description "Application tier security group" --vpc-id vpc-12345678

# Allow traffic only from web tier
aws ec2 authorize-security-group-ingress --group-id sg-app12345 --protocol tcp --port 8080 --source-group sg-web12345
```

### Network Access Control Lists (NACLs)

Implement network-level filtering with NACLs as a second layer of defence:

```bash
# Create custom NACL
aws ec2 create-network-acl --vpc-id vpc-12345678

# Deny all by default, then allow specific traffic
aws ec2 create-network-acl-entry --network-acl-id acl-12345678 --rule-number 100 --protocol tcp --port-range From=80,To=80 --cidr-block 0.0.0.0/0 --rule-action allow

# Associate NACL with subnet
aws ec2 associate-network-acl --network-acl-id acl-12345678 --subnet-id subnet-12345678
```

**Security Tip:** Always test security group and NACL changes in a staging environment before applying to production to avoid service disruptions.

## AWS Web Application Firewall (WAF) Implementation

### WAF Rule Configuration

Deploy AWS WAF to protect web applications from common attacks:

```bash
# Create WAF WebACL
aws wafv2 create-web-acl --name "ProductionWebACL" --scope CLOUDFRONT --default-action Allow={} --description "Production WAF rules"

# Create rate limiting rule
aws wafv2 create-rule-group --name "RateLimitingRules" --scope CLOUDFRONT --capacity 100 --description "Rate limiting protection"

# Associate WAF with CloudFront distribution
aws wafv2 associate-web-acl --web-acl-arn arn:aws:wafv2:us-east-1:ACCOUNT:global/webacl/ProductionWebACL/12345678 --resource-arn arn:aws:cloudfront::ACCOUNT:distribution/DISTRIBUTIONID
```

### Managed Rule Sets

Implement AWS managed rule sets for comprehensive protection:

```json
{
  "Name": "AWSManagedRulesCommonRuleSet",
  "Priority": 1,
  "OverrideAction": {
    "None": {}
  },
  "Statement": {
    "ManagedRuleGroupStatement": {
      "VendorName": "AWS",
      "Name": "AWSManagedRulesCommonRuleSet"
    }
  },
  "VisibilityConfig": {
    "SampledRequestsEnabled": true,
    "CloudWatchMetricsEnabled": true,
    "MetricName": "CommonRuleSetMetric"
  }
}
```

## S3 Bucket Security and Data Protection

### S3 Bucket Hardening

Secure S3 buckets with proper policies and encryption:

```bash
# Block public access at bucket level
aws s3api put-public-access-block --bucket production-data-bucket --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Enable default encryption
aws s3api put-bucket-encryption --bucket production-data-bucket --server-side-encryption-configuration '{
  "Rules": [
    {
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "alias/s3-encryption-key"
      },
      "BucketKeyEnabled": true
    }
  ]
}'

# Enable versioning for data protection
aws s3api put-bucket-versioning --bucket production-data-bucket --versioning-configuration Status=Enabled
```

### S3 Bucket Policies

Implement restrictive bucket policies:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureConnections",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::production-data-bucket",
        "arn:aws:s3:::production-data-bucket/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    },
    {
      "Sid": "AllowVPCEndpointAccess",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::production-data-bucket/*",
      "Condition": {
        "StringEquals": {
          "aws:sourceVpce": "vpce-12345678"
        }
      }
    }
  ]
}
```

## CloudTrail and Logging Configuration

### CloudTrail Setup

Enable comprehensive audit logging with CloudTrail:

```bash
# Create CloudTrail
aws cloudtrail create-trail --name production-audit-trail --s3-bucket-name cloudtrail-logs-bucket --include-global-service-events --is-multi-region-trail --enable-log-file-validation

# Start logging
aws cloudtrail start-logging --name production-audit-trail

# Create event selector for data events
aws cloudtrail put-event-selectors --trail-name production-audit-trail --event-selectors '[
  {
    "ReadWriteType": "All",
    "IncludeManagementEvents": true,
    "DataResources": [
      {
        "Type": "AWS::S3::Object",
        "Values": ["arn:aws:s3:::production-data-bucket/*"]
      }
    ]
  }
]'
```

### CloudWatch Integration

Set up CloudWatch for real-time monitoring and alerting:

```bash
# Create log group for application logs
aws logs create-log-group --log-group-name /aws/application/production

# Create metric filter for error detection
aws logs put-metric-filter --log-group-name /aws/application/production --filter-name ErrorCount --filter-pattern "ERROR" --metric-transformations metricName=ApplicationErrors,metricNamespace=CustomMetrics,metricValue=1

# Create CloudWatch alarm
aws cloudwatch put-metric-alarm --alarm-name "High-Application-Errors" --alarm-description "Alert on high error rate" --metric-name ApplicationErrors --namespace CustomMetrics --statistic Sum --period 300 --threshold 10 --comparison-operator GreaterThanThreshold --evaluation-periods 2
```

## AWS GuardDuty and Threat Detection

### GuardDuty Configuration

Enable GuardDuty for intelligent threat detection:

```bash
# Enable GuardDuty
aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES

# Create threat intelligence set
aws guardduty create-threat-intel-set --detector-id 12345678 --name "CustomThreatIntel" --format TXT --location s3://threat-intel-bucket/indicators.txt --activate

# Configure notifications
aws guardduty create-publishing-destination --detector-id 12345678 --destination-type S3 --destination-properties DestinationArn=arn:aws:s3:::guardduty-findings-bucket,KmsKeyArn=arn:aws:kms:region:account:key/key-id
```

### Security Hub Integration

Centralise security findings with Security Hub:

```bash
# Enable Security Hub
aws securityhub enable-security-hub

# Enable AWS Foundational Security Standard
aws securityhub batch-enable-standards --standards-subscription-requests StandardsArn=arn:aws:securityhub:::ruleset/finding-format/aws-foundational-security-standard

# Create custom insight
aws securityhub create-insight --name "Critical-Findings" --filters '{"SeverityLabel": [{"Value": "CRITICAL", "Comparison": "EQUALS"}]}'
```

## Encryption and Key Management

### AWS KMS Implementation

Implement comprehensive encryption with AWS Key Management Service:

```bash
# Create customer managed key
aws kms create-key --description "Production encryption key" --key-usage ENCRYPT_DECRYPT

# Create alias for easier management
aws kms create-alias --alias-name alias/production-encryption --target-key-id 12345678-1234-1234-1234-123456789012

# Set key policy for role-based access
aws kms put-key-policy --key-id alias/production-encryption --policy-name default --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowKeyAdministration",
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::ACCOUNT:role/KeyAdminRole"
      },
      "Action": "kms:*",
      "Resource": "*"
    }
  ]
}'
```

### Secrets Manager Integration

Securely manage application secrets:

```bash
# Store database credentials
aws secretsmanager create-secret --name "production/database/credentials" --description "Production database credentials" --secret-string '{"username":"dbuser","password":"securepassword123"}'

# Enable automatic rotation
aws secretsmanager rotate-secret --secret-id "production/database/credentials" --rotation-lambda-arn arn:aws:lambda:region:account:function:SecretsManagerRotationFunction
```

## Container Security with Amazon ECS/EKS

### ECS Security Configuration

Secure containerised applications with ECS:

```bash
# Create ECS cluster with container insights
aws ecs create-cluster --cluster-name production-cluster --settings name=containerInsights,value=enabled

# Create task definition with security best practices
aws ecs register-task-definition --family secure-app --task-role-arn arn:aws:iam::ACCOUNT:role/ECSTaskRole --execution-role-arn arn:aws:iam::ACCOUNT:role/ECSExecutionRole --requires-attributes name=com.amazonaws.ecs.capability.ecr-auth --container-definitions '[
  {
    "name": "secure-container",
    "image": "ACCOUNT.dkr.ecr.region.amazonaws.com/secure-app:latest",
    "memory": 512,
    "essential": true,
    "readonlyRootFilesystem": true,
    "user": "1000:1000",
    "linuxParameters": {
      "capabilities": {
        "drop": ["ALL"]
      }
    }
  }
]'
```

### EKS Security Hardening

Implement Kubernetes security best practices on EKS:

```bash
# Create EKS cluster with private endpoint
aws eks create-cluster --name production-eks --version 1.33 --role-arn arn:aws:iam::ACCOUNT:role/EKSServiceRole --resources-vpc-config subnetIds=subnet-12345,subnet-67890,endpointConfigPrivate=true,endpointConfigPublic=false

# Enable EKS Pod Security Policy
kubectl apply -f - <<EOF
apiVersion: policy/v1beta1
kind: PodSecurityPolicy
metadata:
  name: restricted
spec:
  privileged: false
  allowPrivilegeEscalation: false
  requiredDropCapabilities:
    - ALL
  volumes:
    - 'configMap'
    - 'emptyDir'
    - 'projected'
    - 'secret'
    - 'downwardAPI'
    - 'persistentVolumeClaim'
  runAsUser:
    rule: 'MustRunAsNonRoot'
  seLinux:
    rule: 'RunAsAny'
  fsGroup:
    rule: 'RunAsAny'
EOF
```

## Compliance and Governance

### AWS Config Rules

Implement automated compliance checking:

```bash
# Enable AWS Config
aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=arn:aws:iam::ACCOUNT:role/ConfigRole --recording-group allSupported=true,includeGlobalResourceTypes=true

# Create compliance rule for encrypted S3 buckets
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "s3-bucket-server-side-encryption-enabled",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"
  }
}'

# Create custom rule for security group compliance
aws configservice put-config-rule --config-rule '{
  "ConfigRuleName": "security-group-ssh-restricted",
  "Source": {
    "Owner": "AWS",
    "SourceIdentifier": "INCOMING_SSH_DISABLED"
  }
}'
```

### AWS Organisations and SCPs

Implement organisation-wide security policies:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootAccess",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalType": "Root"
        }
      }
    },
    {
      "Sid": "DenyRegionRestriction",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringNotEquals": {
          "aws:RequestedRegion": [
            "eu-west-1",
            "eu-west-2"
          ]
        }
      }
    }
  ]
}
```

## Incident Response and Forensics

### Automated Incident Response

Create automated response workflows with Lambda:

```python
import boto3
import json

def lambda_handler(event, context):
    # Parse GuardDuty finding
    finding = json.loads(event['Records'][0]['Sns']['Message'])
    
    if finding['severity'] >= 7.0:
        # High severity finding - initiate response
        ec2 = boto3.client('ec2')
        
        # Isolate compromised instance
        instance_id = finding['service']['remoteIpDetails']['ipAddressV4']
        
        # Create forensic security group
        forensic_sg = ec2.create_security_group(
            GroupName='forensic-isolation',
            Description='Isolation group for compromised instances'
        )
        
        # Modify instance security group
        ec2.modify_instance_attribute(
            InstanceId=instance_id,
            Groups=[forensic_sg['GroupId']]
        )
        
        # Create snapshot for forensic analysis
        volumes = ec2.describe_volumes(
            Filters=[
                {'Name': 'attachment.instance-id', 'Values': [instance_id]}
            ]
        )
        
        for volume in volumes['Volumes']:
            ec2.create_snapshot(
                VolumeId=volume['VolumeId'],
                Description=f'Forensic snapshot for incident {finding["id"]}'
            )
    
    return {
        'statusCode': 200,
        'body': json.dumps('Incident response executed')
    }
```

### Security Event Analysis

Set up comprehensive logging for forensic analysis:

```bash
# Create dedicated forensics S3 bucket
aws s3api create-bucket --bucket forensics-evidence-bucket --create-bucket-configuration LocationConstraint=eu-west-1

# Configure VPC Flow Logs
aws ec2 create-flow-logs --resource-type VPC --resource-ids vpc-12345678 --traffic-type ALL --log-destination-type s3 --log-destination s3://vpc-flow-logs-bucket/

# Enable DNS query logging
aws route53resolver create-resolver-query-log-config --name "ProductionDNSLogs" --destination-arn arn:aws:s3:::dns-query-logs-bucket
```

## Continuous Security Monitoring

### Security Metrics and Dashboards

Create comprehensive security monitoring dashboards:

```bash
# Create CloudWatch dashboard
aws cloudwatch put-dashboard --dashboard-name "SecurityMetrics" --dashboard-body '{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/GuardDuty", "FindingCount"],
          ["AWS/WAF", "BlockedRequests"],
          ["AWS/CloudTrail", "DataEvents"]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "eu-west-1",
        "title": "Security Events"
      }
    }
  ]
}'
```

### Automated Security Assessments

Implement regular security scanning with Inspector:

```bash
# Create assessment target
aws inspector create-assessment-target --assessment-target-name "Production-Servers" --resource-group-arn arn:aws:inspector:region:account:resourcegroup/12345678

# Create assessment template
aws inspector create-assessment-template --assessment-target-arn arn:aws:inspector:region:account:target/12345678 --assessment-template-name "Security-Assessment" --duration-in-seconds 3600 --rules-package-arns arn:aws:inspector:region:123456789012:rulespackage/0-9hgA516p

# Schedule regular assessments
aws events put-rule --name "WeeklySecurityScan" --schedule-expression "rate(7 days)"
```

**Important** Test automated incident response procedures in a non-production environment to ensure they function correctly without causing service disruptions.

## Advanced Threat Protection

### AWS Shield Advanced Configuration

Enable DDoS protection for critical applications:

```bash
# Subscribe to Shield Advanced
aws shield subscribe-to-proactive-engagement --proactive-engagement-status ENABLED

# Create protection for CloudFront distribution
aws shield create-protection --name "ProductionWebsite" --resource-arn arn:aws:cloudfront::ACCOUNT:distribution/DISTRIBUTIONID

# Configure DRT access
aws shield associate-drt-role --role-arn arn:aws:iam::ACCOUNT:role/DRTAccessRole
```

### Macie Data Discovery

Implement sensitive data discovery with Macie:

```bash
# Enable Macie
aws macie2 enable-macie

# Create classification job
aws macie2 create-classification-job --job-type SCHEDULED --name "SensitiveDataScan" --s3-job-definition '{
  "bucketDefinitions": [
    {
      "accountId": "ACCOUNT",
      "buckets": ["production-data-bucket"]
    }
  ]
}'
```

## Cost Optimisation and Security

### Security Cost Optimisation

Monitor security service costs and optimise spending:

```bash
# Create cost budget for security services
aws budgets create-budget --account-id ACCOUNT --budget '{
  "BudgetName": "SecurityServicesBudget",
  "BudgetLimit": {
    "Amount": "1000",
    "Unit": "USD"
  },
  "TimeUnit": "MONTHLY",
  "BudgetType": "COST",
  "CostFilters": {
    "Service": [
      "Amazon GuardDuty",
      "AWS Security Hub",
      "AWS WAF",
      "AWS Config"
    ]
  }
}'
```

Regular vulnerability assessments and security audits are essential:

```bash
# Install AWS CLI security analysis tools
pip install prowler

# Run comprehensive security audit
prowler aws --services s3,iam,ec2,rds,lambda --output-formats csv,json,html

# Check compliance against CIS benchmarks
prowler aws --checks check21,check22,check23 --compliance cis_1.5_aws

# Generate executive summary report
prowler aws --output-filename security-audit-$(date +%Y%m%d) --output-formats html
```

AWS cloud security requires a comprehensive, multi-layered approach combining identity management, network security, data protection, and continuous monitoring. Regular security assessments, automated threat detection, and incident response capabilities are essential for maintaining a secure cloud infrastructure.

Key AWS security principles include:

- **Identity-first security** with IAM best practices and MFA enforcement
- **Network segmentation** using VPCs, security groups, and NACLs
- **Data protection** through encryption at rest and in transit
- **Continuous monitoring** with CloudTrail, GuardDuty, and Security Hub
- **Automated response** capabilities for threat mitigation
- **Compliance automation** using Config Rules and Organisations
- **Cost-conscious security** balancing protection with operational efficiency

By implementing these security measures and maintaining them consistently, you'll significantly reduce your AWS infrastructure's attack surface and improve your overall security posture.

Remember that cloud security is a shared responsibility model and an ongoing process, not a one-time setup. Regular reviews, updates, and improvements to your security configuration are essential for staying ahead of evolving threats in the cloud environment.

## Expert AWS and Cloud Security Resources

Visit [Chris Binnie - Cloud Native Security](https://www.chrisbinnie.co.uk) for expert insights and practical guides on cloud security, and infrastructure hardening.

For comprehensive Linux server security practices that complement your AWS cloud security strategy, refer to the [Linux Server Security Guide](https://chrisbinnie.github.io/linux-server-security). And, for Kubernetes security see my notes on the [Kubernetes Security Hardening page](https://chrisbinnie.github.io/kubernetes-security).

Author of Cloud Native Security and Linux Server Security books, with extensive experience in enterprise security implementations and AWS Well-Architected Framework reviews.

Linux® is the registered trademark of Linus Torvalds. Use the information from my notes found on these pages at your own risk.

**Related Topics:** AWS Security, Cloud Security, IAM Hardening, VPC Security, AWS WAF, GuardDuty, Kubernetes, CloudTrail, S3 Security, Container Security, DevSecOps, Compliance Automation, Threat Detection, AWS EKS, Managed Kubernetes Service
