# Service Screener

An open source guidance tool for the AWS environment. Click [here](https://bit.ly/ssv2demo) for sample report.

Disclaimer: The generated report has to be hosted locally and MUST NOT be internet accessible

## Overview
Service Screener is a tool that runs automated checks on AWS environments and provides recommendations based on AWS and community best practices. 

AWS customers can use this tool on their own environments and use the recommendations to improve the Security, Reliability, Operational Excellence, Performance Efficiency and Cost Optimisation at the service level. 

This tool aims to complement the [AWS Well Architected Tool](https://aws.amazon.com/well-architected-tool/). 

## How does it work?
Service Screener uses [AWS Cloudshell](https://aws.amazon.com/cloudshell/), a free serivce that provides a browser-based shell to run scripts using the AWS CLI. It runs multiple `describe` and `get` API calls to determine the configuration of your environment.

## How much does it cost?
Running this tool is free as it is covered under the AWS Free Tier. If you have exceeded the free tier limits, each run will cost less than $0.01.

## Prerequisites
1. Please review the [DISCLAIMER](./DISCLAIMER.md) before proceeding. 
2. You must have an existing AWS Account.
3. You must have an IAM User with sufficient read permissions. Here is a sample [policy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html). Additionally, the IAM User must also have the following permissions:
   a. AWSCloudShellFullAccess
   b. cloudformation:CreateStack
   c. cloudformation:DeleteStack

## Installing service-screener V2
1. [Log in to your AWS account](https://docs.aws.amazon.com/cloudshell/latest/userguide/getting-started.html#start-session) using the IAM User with sufficient permissions described above. 
2. Launch [AWS CloudShell](https://docs.aws.amazon.com/cloudshell/latest/userguide/getting-started.html#launch-region-shell) in any region. 

<details>
<summary>Launch AWS Cloudshell Walkthrough</summary>
   
![Launch AWS CloudShell](https://d39bs20xyg7k53.cloudfront.net/services-screener/p1-cloudshell.gif)
</details>

In the AWS CloudShell terminal, run this script this to install the dependencies:
```bash
cd /tmp
python3 -m venv .
source bin/activate
python3 -m pip install --upgrade pip
rm -rf service-screener-v2
git clone https://github.com/aws-samples/service-screener-v2.git
cd service-screener-v2
pip install -r requirements.txt
alias screener="python3 $(pwd)/main.py"

```
<details>
<summary>Install Dependecies Walkthrough</summary>
   
![Install dependencies](https://d39bs20xyg7k53.cloudfront.net/services-screener/p2-dependencies.gif)
</details>

## Using Service Screener
When running Service Screener, you will need to specify the regions and services you would like it to run on. It currently supports Amazon Cloudfront, AWS Cloudtrail, Amazon Dynamodb, Amazon EC2, Amazon EFS, Amazon RDS, Amazon EKS, Amazon Elasticache, Amazon Guardduty, AWS IAM, Amazon Opensearch, AWS Lambda, and Amazon S3.

We recommend running it in all regions where you have deployed workloads in. Adjust the code samples below to suit your needs then copy and paste it into Cloudshell to run Service Screener. 

**Example 1: Run in the Singapore region, check all services**
```
screener --regions ap-southeast-1 
```

**Example 2: Run in the Singapore region, check only Amazon S3**
```
screener --regions ap-southeast-1 --services s3
```

**Example 3: Run in the Singapore & North Virginia regions, check all services**
```
screener --regions ap-southeast-1,us-east-1
```

**Example 4: Run in the Singapore & North Virginia regions, check RDS and IAM**
```
screener --regions ap-southeast-1,us-east-1 --services rds,iam
```

**Example 5: Run in the Singapore region, filter resources based on tags (e.g: Name=env Values=prod and Name=department Values=hr,coe)**
```
screener --regions ap-southeast-1 --tags env=prod%department=hr,coe
```

**Example 6: Run in all regions and all services**
```
screener --regions ALL
```

### Other parameters
```bash
##mode
--mode api-full | api-raw | report

# api-full: give full results in JSON format
# api-raw: raw findings
# report: generate default web html
```
<details>
<summary>Get Report Walkthrough</summary>
   
![Get Report](https://d39bs20xyg7k53.cloudfront.net/services-screener/p3-getreport.gif)
</details>

### Downloading the report
The output is generated as a ~/service-screener-v2/output.zip file. 
You can [download the file](https://docs.aws.amazon.com/cloudshell/latest/userguide/working-with-cloudshell.html#files-storage) in the CloudShell console by clicking the *Download file* button under the *Actions* menu on the top right of the Cloudshell console. 

<details>
<summary>Download Output & Report Viewing Walkthrough</summary>
   
![Download Output](https://d39bs20xyg7k53.cloudfront.net/services-screener/p4-outputzip.gif)

Once downloaded, unzip the file and open 'index.html' in your browser. You should see a page like this:

![front page](https://d39bs20xyg7k53.cloudfront.net/services-screener/service-screener.jpg?v1)

Ensure that you can see the service(s) run on listed on the left pane.
You can navigate to the service(s) listed to see detailed findings on each service. 
</details>

<details>
<summary>Sample Output Walkthrough</summary>
   
![Sample Output](https://d39bs20xyg7k53.cloudfront.net/services-screener/p5-sample.gif)
</details>

## Using the report 
The report provides you an easy-to-navigate dashboard of the various best-practice checks that were run. 

Use the left navigation bar to explore the checks for each service. Expand each check to read the description, find out which resources were highlighted, and get recommendations on how to remediate the findings.  

## Contributing to service-screener
We encourage public contributions! Please review [CONTRIBUTING](./CONTRIBUTING.md) for details on our code of conduct and development process.

## Contact
Please review [CONTRIBUTING](./CONTRIBUTING.md) to raise any issues. 

## Security
See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License
This project is licensed under the Apache-2.0 License.

