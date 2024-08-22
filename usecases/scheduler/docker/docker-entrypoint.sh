#!/bin/sh

# Source .bashrc to ensure environment variables are available
source ~/.bashrc

# Change to the service-screener-v2 directory
cd service-screener-v2

# Run the main.py script
python3 main.py $PARAMS

# Get the current date
CURRENT_DATE=$(date +"%Y%m%d")

# create folder and add all the files in
mkdir -p "$CURRENT_DATE"
cp output.zip "$CURRENT_DATE"

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
aws s3 cp "$CURRENT_DATE" s3://$S3_OUTPUT_BUCKET/$CONFIG_NAME/$CURRENT_DATE --recursive