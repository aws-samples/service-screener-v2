# Service Screener Developer Guide

## Pre-requisite
1. git account
1. fork the master repository from aws-samples
1. clone the forked repo to local machine
1. setup aws-cli follows aws official documentation: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html 
1. Setup necessary IAM Users with readOnly permission. 
1. Generate Accesskey & Secret combination to be used by local machine
1. Run ```aws configure --profile <name>``` and follow through the setup wizard

## Preparation on Mac environment
```bash
# You may opt-in to develop in other PHP version, the following guide is to 
brew install php@7.4
php -v # make sure it is version 7.4 

## Then you may follow the official instruction to install composer & php-sdk
```