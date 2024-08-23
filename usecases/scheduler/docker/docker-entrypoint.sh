#!/bin/sh

# Source .bashrc to ensure environment variables are available
. ~/.bashrc

# Change to the service-screener-v2 directory
cd service-screener-v2

# Check if $CROSSACCOUNT paramater is not empty
is_valid_json() {
  echo "$1" | jq . >/dev/null 2>&1
  return $?
}

if [ -n "$CROSSACCOUNTS" ]; then
    if is_valid_json "$CROSSACCOUNTS"; then
        echo "Valid JSON"
        echo $CROSSACCOUNTS > crossAccounts.json
        crossAccountsParam=' --crossAccounts 1 '
    else
        echo "Invalid JSON, will run without cross account"
        crossAccountsParam=''
    fi
fi

# Check if need to run for ALL regions
if echo "$PARAMS" | grep -q "ALL"; then
    echo "y" | python3 main.py $PARAMS $crossAccountsParam 
else
    python3 main.py $PARAMS $crossAccountsParam 
fi

# Get the current date
CURRENT_DATE=$(date +"%Y%m%d")

# Create folder and add all the files in
mkdir -p "$CURRENT_DATE"

# Loop through the folders in adminlte/aws/, copy the folder names if its not "res" and the file workItem.xlsx inside each to a new folder
for folder in adminlte/aws/*; do
    folder_name=$(basename $folder)
    if [ "$folder_name" != "res" ]; then
            mkdir "$CURRENT_DATE"/$folder_name
            cp $folder/workItem.xlsx "$CURRENT_DATE"/$folder_name/
            echo "Added $folder_name"
    fi
done

# Upload the workItems to S3 with file name as current date
aws s3 cp "$CURRENT_DATE" s3://$S3_OUTPUT_BUCKET/$CONFIG_ID/$CURRENT_DATE --recursive

# Upload output.zip to S3
aws s3 cp output.zip s3://$S3_OUTPUT_BUCKET/$CONFIG_ID/$CURRENT_DATE/$CURRENT_DATE.output.zip