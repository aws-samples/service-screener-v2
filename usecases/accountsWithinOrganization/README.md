## Overview

As users launch more and more workload in AWS, users will eventually move themselves towards [AWS Organizations](https://aws.amazon.com/organizations/) to ease the management of their AWS workloads. For user to execute Service-Screener (SS) in one account is direct, but it can become tedious and repetitive if user has multiple AWS accounts within the same organization.

## Solutions

SS today support crossAccounts scanned, which required users to manually setup the crossAccounts.json file by providing the list of AWS accountID, roleNameToBeAssumed, and externalID. To accelerate the crossAccounts.json creation, you can now run ```python3 organizationAccountsInit.py``` and the crossAccounts.json will be generated based on the input given. 

Then, you can execute the following to scan all your accounts within your organization
```
screener --regions ALL --crossAccounts 1
```

