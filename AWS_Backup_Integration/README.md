# AWS Backup Elastio Integration to Help Protect Data from Ransomware, Malware, and Corruption.

Authored by: Adam Nelson, CTO of Elastio, Cris Daniluk, AWS Security Architect.

One of the challenges with using AWS Backup is that customers often cannot be sure if their recovery points are usable and free from cyber threats and corruption. This can spread infected copies of data across different regions and accounts and invalidate local restores and disaster recovery. 

Elastio scans data for threats and corruption in AWS backup recovery points to address this issue, followed by recovery testing to ensure fast and clean restoration. This minimizes the risk of further infecting other resources and ensures that customers can quickly and easily recover their data to a clean state and with minimal data loss, downtime and reputational damage.

The results of each scan can be made available to Amazon S3 or sent to popular security platforms such as AWS Audit Manager, AWS SecurityHub, Splunk, and Datadog. This gives customers greater visibility into their backup data and allows them to protect against potential threats and corruption proactively.

![Picture1](https://user-images.githubusercontent.com/81738703/219877966-e0eea261-0946-412a-80c3-d03511c55fa7.png)

In the event that a cyber threat is detected and needs to be remediated, Elastio provides the ability to provide historical context and reconstitute material information for forensic interrogation from its cyber vault. 

Customers can recover entire instances, selected volumes, or individual files in a secure and isolated environment.  The entire process is run from within the customer’s AWS account. Elastio cannot view, access, or gain custody of customer data. 

Elastio imports AWS Backups as globally deduplicated and compressed, resulting in improved scan performance, shorter recovery times, and cost savings. The global deduplication process eliminates duplicated data blocks across multiple snapshots, reducing the amount of object storage required to store them. The compression process reduces the size of the snapshots, further reducing the storage and time required to transfer the data.

## AWS Backup and Elastio Architectures

### Single Account Deployment

![Picture2](https://user-images.githubusercontent.com/81738703/219877974-18b98685-e50a-49f3-971f-a80060b24ba5.png)

1. AWS Backup creates a recovery point for an EC2 instance.
2. An EventBridge event is triggered when the backup for the EC2 instance is completed.
3. The event triggers a Lambda function that invokes an Elastio processing pipeline. The pipeline imports the recovery point and performs a cyber scan on all associated objects, including the EBS volumes and the AMI. 
4. After the pipeline completes, detailed artifacts are generated and sent to EventBridge. 
5. A Job Status Lambda function is triggered to copy the artifacts to an Amazon S3 bucket. 
6. The artifacts are stored in S3 and sent to Securityhub. Alternatively, the lambda can be modified to send artifacts to any system, including Datadog, and Splunk.

### Cross Account Configuration

![Picture3](https://user-images.githubusercontent.com/81738703/219877989-478ccc6f-1780-4064-a39c-48a0b3965b61.png)

1. AWS Backup creates a recovery point for an EC2 instance.
2. An EventBridge event is triggered when the backup for the EC2 instance is completed.
3. The event triggers a Lambda function that invokes an Elastio processing pipeline. The pipeline imports the recovery point and performs a cyber scan on all associated objects, including the EBS volumes and the AMI. 
4. After the pipeline completes, detailed artifacts are generated and sent to EventBridge. 
5. A Job Status Lambda function is triggered to copy the artifacts to an Amazon S3 bucket. You can learn more about the Job Status Lambda function [here](https://docs.aws.amazon.com/step-functions/latest/dg/sample-project-job-poller.html).
6. The artifacts are stored in S3 and sent to Securityhub. Alternatively, the lambda can be modified to send artifacts to any system, including Datadog, and Splunk.

### Deploying AWS Backup CloudFormation

1. Log in to the AWS Account where the AWS Backup Vault exists.
2. Review the YAML below and deploy by Selecting CloudFormation and importing the YAML file.
3. From CloudFormation console, select Create Stack, Select "With New Resources".
4. Select "Upload Template File" and upload the YAML file.
5. Enter the stack name "aws-backup-elastio-integration"
6. Enter an S3 bucket name.  
7. Enter the Tag name. Recovery points with this tag assigned will be scanned for vulnerabilities.
8. Optionally use all defaults and follow the wizard to create the stack.

  **Elastio_stack_with_SecurityHub.yaml**
```
AWSTemplateFormatVersion: 2010-09-09
Description: Deploys the Integration for Elastio with AWS Backup
Metadata:
  AWS::CloudFormation::Interface:
    ParameterGroups:
      - Label:
          default: Elastio Integration Configuration
        Parameters: 
            - LogsBucketName  
            - LambdaTriggerTag
            - StackBinaryURL
    ParameterLabels:
      LogsBucketName:
        default: S3 Bucket for Elastio Logs and Data 
      LambdaTriggerTag:
        default: RecoveryPoint Tag to initiate Elastio Scan
      StackBinaryURL:
        default: The URL for the StackBinary Zip File         
Parameters:
  LogsBucketName:
    Description: The S3 Bucket Name where the Job Logs and Reports are to be stored. 
    Type: String
  LambdaTriggerTag:
    Description: The Tag in an AWS Backup RecoveryPoint that will initiate an Elastio Scan
    Type: String
  StackBinaryURL:
    Description: The URL for the StackBinary Zip File
    Type: String    
    Default: 'https://observer-solution-artefacts.s3.us-west-2.amazonaws.com/aws-backup-elastio-integration.zip'    
  
Resources: 
  SolutionLocalCacheBucket:
    Type: "AWS::S3::Bucket"
    DeletionPolicy: Delete
    UpdateReplacePolicy: Retain
    Properties:
      BucketEncryption:
        ServerSideEncryptionConfiguration:
          - ServerSideEncryptionByDefault:
              SSEAlgorithm: AES256
      PublicAccessBlockConfiguration:
        BlockPublicAcls: true
        BlockPublicPolicy: true
        IgnorePublicAcls: true
        RestrictPublicBuckets: true  

  CleanupSolutionLocalCacheBucketOnDelete:
    Type: Custom::CleanupBucket
    Properties:
      ServiceToken: !GetAtt GlobalCfnCodeReplicatorLambda.Arn
      S3BucketToCleanup: !Ref SolutionLocalCacheBucket  

  CopySolutionToLocalCacheBucket:
    Type: Custom::ReplicateSolutionBinaries
    Properties:
      ServiceToken: !GetAtt GlobalCfnCodeReplicatorLambda.Arn
      SolutionDestinationBucket: !Ref SolutionLocalCacheBucket
      SolutionURL: !Ref StackBinaryURL

  GlobalCfnCodeReplicatorLambda:
    Type: AWS::Lambda::Function
    Metadata:
        cfn_nag:
          rules_to_suppress:
            - id: W89
              reason: "Custom resource deployed in default VPC"
            - id: W92
              reason: "ReservedConcurrentExecutions not needed since this function runs once when CloudFormation deploys"    
    Properties:
      Code:
        ZipFile: |-
          #!/usr/bin/env python
          # -*- coding: utf-8 -*-
          import json
          import boto3
          import urllib3
          import os
          import shutil
          from urllib.parse import urlparse
          physical_resource_id = 'GlobalCfnCodeReplicator'  
          def process_bucket_cleanup_request(bucket_name):
              print(f"process_bucket_cleanup_request starting for bucket_name : {bucket_name}")
              s3 = boto3.resource('s3')
              bucket_to_delete = s3.Bucket(bucket_name)
              response = bucket_to_delete.objects.all().delete()
              print(f"process_bucket_cleanup_request all object delete done. Response : {response}")
        
          def download_url(url, save_path):
            c = urllib3.PoolManager()
            with c.request('GET',url, preload_content=False) as resp, open(save_path, 'wb') as out_file:
                shutil.copyfileobj(resp, out_file)
            resp.release_conn()
            
          def lambda_handler(event, context):
            try:
                print(f'Handling event : {event}')
                request_type = event.get('RequestType')              
                solution_url = event['ResourceProperties'].get('SolutionURL')
                solution_bucket = event['ResourceProperties'].get('SolutionDestinationBucket')
                response_data = {
                    'RequestType': request_type,
                    'SolutionURL' : solution_url,
                    'SolutionDestinationBucket' : solution_bucket
                }
                if request_type == 'Create' or request_type == 'Update':
                    if solution_url:
                        print(f'downloading file from : {solution_url}')
                        a = urlparse(solution_url)
                        original_file_name = os.path.basename(a.path)
                        temp_file_name = '/tmp/'+original_file_name
                        download_url(solution_url,temp_file_name)
                        file_size = (os.stat(temp_file_name).st_size / 1024)
                        print(f'Downloaded report to File : {temp_file_name} , Size : {file_size}')
                        #Upload this to the Bucket
                        s3_client = boto3.client('s3')
                        print(f"uploading payload to : {solution_bucket} at {original_file_name}")
                        extraArgsForUpload = {'ACL':'bucket-owner-full-control', 'Tagging':'Source=StackBinaryURL'}
                        s3_client.upload_file(Filename=temp_file_name, Bucket=solution_bucket, Key='bin/' + original_file_name,ExtraArgs=extraArgsForUpload)
                elif request_type == 'Delete':
                    solution_bucket = event['ResourceProperties'].get('S3BucketToCleanup')
                    if solution_bucket:
                        process_bucket_cleanup_request(solution_bucket)
                    
                send(event, context, 'SUCCESS', response_data, physical_resource_id)
            except Exception as e:
                print(f'{e}')
                send(event, context, 'FAILED', response_data, physical_resource_id)
          def send(event, context, response_status, response_data, physical_resource_id, no_echo=False):
            http = urllib3.PoolManager()
            response_url = event['ResponseURL']
            json_response_body = json.dumps({
                'Status': response_status,
                'Reason': f'See the details in CloudWatch Log Stream: {context.log_stream_name}',
                'PhysicalResourceId': physical_resource_id,
                'StackId': event['StackId'],
                'RequestId': event['RequestId'],
                'LogicalResourceId': event['LogicalResourceId'],
                'NoEcho': no_echo,
                'Data': response_data
            }).encode('utf-8')
            headers = {
                'content-type': '',
                'content-length': str(len(json_response_body))
            }
            try:
                http.request('PUT', response_url,
                             body=json_response_body, headers=headers)
            except Exception as e:  # pylint: disable = W0703
                print(e)
      Description: Copy Solutions Binary to Local Cache Bucket
      Handler: index.lambda_handler
      Role : !GetAtt ElastioStatusHandlerLambdaRole.Arn
      Runtime: python3.10
      Architectures: 
            - arm64
      Timeout: 300
  ProcessAWSBackupVaultStatusEventRuleForElastio: 
    Type: AWS::Events::Rule
    Properties: 
      Name: ProcessAWSBackupVaultStatusEventRuleForElastio
      Description: "Rule to direct AWS Backup Events to Elastio Status Handler Lambda"
      State: "ENABLED"
      EventPattern: 
        source:
          - 'aws.backup'
        detail-type:
          - 'Recovery Point State Change'
      Targets: 
        - Arn: !GetAtt
                  - ElastioStatusHandlerLambda
                  - Arn
          Id: "ProcessAWSBackupEventsUsingLambda" 
          
  ProcessAWSBackupVaultStatusEventRuleForElastioInvokePermission:
    Type: 'AWS::Lambda::Permission'
    Properties:
      Action: 'lambda:InvokeFunction'
      FunctionName: !Ref ElastioStatusHandlerLambda
      Principal: events.amazonaws.com
      SourceArn: !Sub ${ProcessAWSBackupVaultStatusEventRuleForElastio.Arn}
      
  ElastioStatusHandlerLambda:
    Type: AWS::Lambda::Function
    Metadata:
        cfn_nag:
          rules_to_suppress:
            - id: W89
              reason: "NA"
            - id: W92
              reason: "NA"   
    DependsOn: CopySolutionToLocalCacheBucket              
    Properties:
      Code:
        S3Bucket: !Ref SolutionLocalCacheBucket
        S3Key: 'bin/aws-backup-elastio-integration.zip'
      Description: Handle AWS Backup and Elastio Scan results
      Handler: lambda_handler.handler
      Role : !GetAtt ElastioStatusHandlerLambdaRole.Arn
      Runtime: python3.10
      Architectures: 
            - arm64      
      Timeout: 900
      Environment:
        Variables:
          ElastioStatusEB : !Ref ElastioJobStatusEventBus 
          LogsBucketName: !Ref LogsBucketName
          ElastioImportLambdaARN : !Sub "arn:${AWS::Partition}:lambda:${AWS::Region}:${AWS::AccountId}:function:elastio-bg-jobs-service-aws-backup-rp-import"
          LambdaTriggerTag: !Ref LambdaTriggerTag
  ElastioJobStatusEventBus:
    Type: AWS::Events::EventBus
    Properties:
      Name: !Join [ '', ['ElastioJobStatusEventBus-', !Ref 'AWS::AccountId'] ]

  ElastioStatusEventBridgeInvokePermission:
    Type: 'AWS::Lambda::Permission'
    Properties:
      Action: 'lambda:InvokeFunction'
      FunctionName: !Ref ElastioStatusHandlerLambda
      Principal: events.amazonaws.com
      SourceArn: !Sub ${ElastioStatusEventRule.Arn}    
  
  ElastioStatusEventRule: 
    Type: AWS::Events::Rule
    Properties: 
      Description: "Send Elastio events to Lambda"
      EventBusName: !Ref ElastioJobStatusEventBus
      State: "ENABLED"
      EventPattern: 
        source:
          - 'elastio.iscan'
      Targets: 
        - Arn: !GetAtt ElastioStatusHandlerLambda.Arn
          Id: "ElastioStatusEvent"
  
  ElastioJobStatusEventBusPolicy:
    Type: AWS::Events::EventBusPolicy
    Properties: 
        EventBusName: !Ref ElastioJobStatusEventBus
        StatementId: "ElastioStatusEventBridgePolicyStmt"
        Statement: 
            Effect: "Allow"
            Principal: "*"
            Action: "events:PutEvents"
            Resource: !GetAtt "ElastioJobStatusEventBus.Arn"

  ElastioStatusHandlerLambdaRole:
    Type: 'AWS::IAM::Role'
    Metadata:    
      cfn_nag:
        rules_to_suppress:
          - id: F3
          - id: W11
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: 'sts:AssumeRole'
      ManagedPolicyArns:
          - !Sub 'arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
      Policies:
          - PolicyName: invokeLambda
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
              - Effect: Allow
                Action:
                - lambda:InvokeFunction
                Resource: '*'           
          - PolicyName: s3Permissions
            PolicyDocument:
              Statement:
              - Effect: Allow
                Action:
                  - kms:GenerateDataKey
                  - kms:Decrypt
                  - kms:Encrypt                  
                  - s3:PutObject*
                  - s3:GetObject*
                  - s3:DeleteObject
                  - s3:*BucketNotification
                  - s3:GetBucketLocation
                  - s3:ListBucket
                  - s3:ListBucketMultipartUploads
                  - s3:ListMultipartUploadParts
                  - s3:AbortMultipartUpload                  
                Resource:
                  - !Sub 'arn:${AWS::Partition}:s3:::${LogsBucketName}/*'
                  - !Sub 'arn:${AWS::Partition}:s3:::${LogsBucketName}'
                  - !Sub 'arn:${AWS::Partition}:s3:::${SolutionLocalCacheBucket}/*'
                  - !Sub 'arn:${AWS::Partition}:s3:::${SolutionLocalCacheBucket}'                    
          - PolicyName: logStreamPermissions
            PolicyDocument:
              Statement:                       
              - Effect: Allow
                Action:
                  - 'logs:CreateLogGroup'
                  - 'logs:CreateLogStream'
                  - 'logs:PutLogEvents'
                Resource: !Sub 'arn:${AWS::Partition}:logs:*:*:*'   
          - PolicyName: secHubPermissions
            PolicyDocument:
              Statement:                       
              - Effect: Allow
                Action:
                  - 'securityhub:BatchImportFindings'
                  - 'securityhub:CreateInsight'
                Resource: 
                  - !Sub 'arn:${AWS::Partition}:securityhub:*:${AWS::AccountId}:product/*/*'
                  - !Sub 'arn:${AWS::Partition}:securityhub:*:${AWS::AccountId}:hub/default'        
            
Outputs:
  StackName:
    Value: !Ref AWS::StackName
```

### Deploying Elastio

Elastio is deployed in the account that contains the AWS Backup Vault in which you want the recovery points scanned for cyber threats.

1. From [elastio.com](http://www.elastio.com) select “login” and “create new account”.  Follow the process to create a new tenant.
2. From the tenant, select On-Boarding and select Deploy.
3. Deploy the CFN in the same account that contains the AWS Backup Vault.
4. Deploy the Cloud Connector in the same region and the AWS Backup Vault.
5. Proceed to deploy the Job Trigger and Job Status Lambda’s as described above.
6. If you have existing AWS Backup policies, they will work without changes. If not, create a policy to protect your EC2 instances.

### Run Your First Backup and Scan

1. From the AWS Backup console, go to Dashboard and select "Create on-demand backup".
2. Select EC2 or EBS to backup.
3. Add Tag that was specified during CFN Stack creation. E.g. `scan` - tag name specified during stack creation; `scan:true` - tag assigned to backup.
4. Press "Create on-demand backup" button.
5. The scan results artifacts will be available in the S3 bucket provided in the CloudFormation definition. The results are presented in JSON.

From the Elastio Tenant.
1. Select Jobs
2. View the import and iscan jobs to validate the process.
3. Once complete, from the job list, select the recovery point id and view the results.  

![image](https://user-images.githubusercontent.com/81738703/219956284-582a780c-463b-4b69-81b7-8500b44a7962.png)

### Conclusion
By using Elastio to enhance AWS Backup, organizations can secure their cloud data, reduce data loss and downtime, and improve Recovery Time Objectives (RTO) in case of an attack or application failure.   Elastio imports AWS Backups as globally deduplicated and compressed, resulting in improved scan performance, shorter recovery times, and cost savings.

AWS customers can contact [sales@elastio.com](mailto:sales@elastio.com) to set up a demo of Elastio or they can download the product from [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-jvce2rake3i3i?sr=0-1&ref_=beagle&applicationId=AWSMPContessa). A free tier that covers 1TB of protected data with a seven-day retention period and a free 30-day trial with full functionality and unlimited retention are both available. See [Elastio’s pricing page](https://elastio.com/pricing/) for full details. 
