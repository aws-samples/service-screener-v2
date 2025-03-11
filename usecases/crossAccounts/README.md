## Overview

As a security best practice, it is recommended to organise your AWS environment in separate accounts as it provides a logical separation of the workload and data that it holds. These AWS accounts can be managed by [AWS Organizations](https://aws.amazon.com/organizations/). It will thus provide much convenience for the security/audit team to have a view of whether workloads and accounts are managed in accordance to best practices. In this use case, Service Screener allows you to run automated checks on the accounts within your organization. 

This utilised the idea of provisioning cross-account access for Service Screener to assume so as to check the different accounts against best practices. This is done through the use of cross-account IAM role — an IAM role that includes a [trust policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html#term_trust-policy) that allows principals in another AWS account to assume that role. 

Once the checks are being done, the report can be downloaded from the CloudShell which will segregate the findings based on account number.

![Architecture Diagram](/usecases/crossAccounts/static/images/p1-architecture-diagram.png)

## Using Service Screener across multiple accounts

Additional IAM Policy is required for cross accounts to work. We need permission to set iam assume-role SecurityToken to use V2 via **iam:SetSecurityTokenServicePreferences** (Service-Screener will first check the current version. If is already V2, no action required. If it is V1, it will set to V2 temporary while assume all the roles, then set it back to V1). We need V2 here as V1 does not support the default-non-opt-in regions (e.g: Jakarta)

When running Service Screener across the targeted accounts, follow these steps to create the necessary role needed for Service Screener to assume:

1. Download the [CloudFormation template](https://github.com/aws-samples/service-screener-v2/blob/cebd00c943b5f74d9384a5ff5a26f98ea114e445/usecases/crossAccounts/crossAccountRoleCF.yml).
2. For each of the accounts that you would like to run Service Screener on:
    1. Navigate to [CloudFormation](https://console.aws.amazon.com/cloudformation/home).
    2. Create a new stack set by clicking on **Create StackSets**
    3. On the **Create StackSets** page, perform the following steps:
        1. For **Specify template**, choose Upload a template file
        2. Choose the file (*crossAccountRoleCF.yml*) that you have downloaded in the previous step.
        3. Choose **Next**
    4. On the **Specify StackSet Details** page, perform the following steps:
        1. For **StackSet name**, enter a name that you can identify with and a description in the next box
        2. For the **Parameters**,
            1. ***ExecAccountNo*** - This indicates the AWS 12-digit account number for the account you are running the Service Screener from
            2. ***ExternalID*** - This indicates the unique identifier that third parties use to access a customer’s account. This is used to grant access from one AWS role to another.
            3. ***RoleName*** - This indicates the name of role created by the CloudFormation template. You can keep this as default (*ServiceScreenerAssumeRole*)
    5. In the **Set deployment options** page, select **us-east-1** for region to be deployed to
    6. Review all the information, and check the acknowledgement box. Press **Submit**

Now that the cross-account role is created, you will include the account numbers in the crossAccounts.json file. For an example of how the json look like, please look at [crossAccounts.sample.json](https://github.com/aws-samples/service-screener-v2/blob/main/crossAccounts.sample.json)

1. Create the file with the name - crossAccounts.json
2. The following parameters are included in the json:
    1. **“general”** — This pertains to the account that you are running Service Screener from
        1. ***IncludeThisAccount*** — Set to “true” if you would like Service Screener to run on the particular account that you run it from
        2. ***ExternalId***
        3. ***RoleName***
    2. **“accountLists”** — List the AWS accounts that you wish to run Service Screener on
3. Configure the crossAccounts.json file with the relevant information and add this file to the CloudShell. You can do so by going to the Actions and select Upload file and upload crossAccounts.json

![CloudShell Console Image](/usecases/crossAccounts/static/images/p2-cloudshell.png)

4. Move the file to the service-screener-v2 directory
```
mv ~/crossAccounts.json ~/service-screener-v2/
```
Once you have completed that, you are ready to run Service Screener across multiple accounts based on the account number listed in the crossAccounts.json by running any of the commands listed below:

**Example #1: Run Service Screener across multiple account, in us-east-1**
```
screener --regions us-east-1 --crossAccounts 1
```
**Example #2: Run Service Screener across multiple accounts, in all regions**
```
screener --regions ALL --crossAccounts 1
```

## Downloading the report

The output is generated as a ***~/service-screener-v2/output.zip*** file. You can download the file in the CloudShell console by clicking the Download file button under the Actions menu on the top right of the Cloudshell console.

Once downloaded, unzip the file and open 'index.html' in your browser. You should see a page like this:

![SS Report](/usecases/crossAccounts/static/images/p3-report.png)

You will be able to toggle between the accounts by selecting the accounts that you would like to view the report from the top right drop down lost. Use the left navigation bar to explore the checks for each service. Expand each check to read the description, find out which resources were highlighted, and get recommendations on how to remediate the findings.
