#!/bin/sh

# Source .bashrc to ensure environment variables are available
source ~/.bashrc

# Change to the service-screener-v2 directory
cd service-screener-v2

# Check if $CROSSACCOUNT paramater is empty

## TESTING PURPOSES
S3_OUTPUT_BUCKET='service-screener-results-058264210765'
PARAMS=' --regions ALL '
CONFIG_ID='config1'
CROSSACCOUNTS=''

if [ -n "$CROSSACCOUNTS" ]; then
    echo "CROSSACCOUNTS is not empty"
    echo $CROSSACCOUNTS > crossAccounts.json
    crossAccountsParam=' --crossAccounts 1 '
fi

# Run the main.py script
# check if $PARAMS contains '--regions ALL'
# case "--regions ALL" in
#     *"$PARAMS"*) 
#         echo "The string contains '--region ALL'"
#         python3 main.py $PARAMS $crossAccountsParam y 
#         ;;
#     *) 
#         python3 main.py $PARAMS $crossAccountsParam 
#         ;;
# esac

if echo "$PARAMS" | grep -q "ALL"; then
    echo "The string contains '--region ALL'"
    echo "n" | python3 main.py $PARAMS $crossAccountsParam 
    
else
    echo "The string does not contain '--region ALL'"
    python3 main.py $PARAMS $crossAccountsParam 
fi

# Get the current date
CURRENT_DATE=$(date +"%Y%m%d")

# create folder and add all the files in
mkdir -p "$CURRENT_DATE"
cp output.zip "$CURRENT_DATE/$CURRENT_DATE.output.zip" 

# loop through the folders in adminlte/aws/, copy the folder names if its not "res" and the file workItem.xlsx inside each to a new folder
for folder in adminlte/aws/*; do
    folder_name=$(basename $folder)
    if [ "$folder_name" != "res" ]; then
            mkdir "$CURRENT_DATE"/$folder_name
            cp $folder/workItem.xlsx "$CURRENT_DATE"/$folder_name/
            echo "Added $folder_name"
        else
            echo "Skipping 'res' folder"
    fi
done

# Upload the output.zip file to S3 with file name as current date
aws s3 cp "$CURRENT_DATE" s3://$S3_OUTPUT_BUCKET/$CONFIG_ID/$CURRENT_DATE --recursive