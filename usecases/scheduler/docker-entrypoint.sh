#!/bin/sh

# Source .bashrc to ensure environment variables are available
source ~/.bashrc

# Change to the service-screener-v2 directory
cd service-screener-v2

# Run the main.py script
python3 main.py $PARAMS

# Get the current date
CURRENT_DATE=$(date +"%Y-%m-%d")

# Upload the output.zip file to S3 with file name as current date
aws s3 cp output.zip s3://$S3_OUTPUT_BUCKET/$CURRENT_DATE.zip