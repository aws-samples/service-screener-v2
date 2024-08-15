# Service Screener Developer Guide

## Preparation on Mac environment
```bash

## Install homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
# PLEASE READ
# FOLLOW THE 'NEXT STEP' shows after installation
# THERE ARE 2 COMMANDS TO COPY/PASTE to set the environment variables correctly

## Install Python, and set the alias in ~/.zprofile or ~/.bash_profile
brew install python@3.12
which python3.12
alias python3=... <to the path above>, #also setup this in ~/.zprofile?

## Install AWS CLI
curl "https://awscli.amazonaws.com/AWSCLIV2.pkg" -o "AWSCLIV2.pkg"
sudo installer -pkg AWSCLIV2.pkg -target /

# Setup AWS Profile
aws configure --profile ss

# Setup before running screener command
python3 -m venv .
source bin/activate
python3 -m pip install --upgrade pip
pip install -r requirements.txt
alias screener="python3 $(pwd)/main.py"

## When executing SS locally
screener --regions ap-southeast-1 --profile ss
```

## Pre-requisite
1. Login to your Git account
1. Fork the master repository from aws-samples
1. git clone <your forked repository url>
1. setup aws-cli follows aws official documentation: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html 
1. Setup necessary IAM Users with readOnly permission. 
1. Generate Accesskey & Secret combination to be used by local machine
1. Run ```aws configure --profile <name>``` and follow through the setup wizard
