#!/bin/bash
set -e

# Function to validate AWS services
validate_services() {
    local input_services=$1
    local valid_services=$(aws servicecatalog list-services --query 'ServiceSummaries[].Name' --output text)
    local invalid_services=()

    IFS=',' read -ra services <<< "$input_services"
    for service in "${services[@]}"; do
        service=$(echo $service | xargs)
        if [[ ! $valid_services =~ (^|[[:space:]])$service($|[[:space:]]) ]]; then
            invalid_services+=($service)
        fi
    done

    if [ ${#invalid_services[@]} -eq 0 ]; then
        echo "All specified services are valid."
        return 0
    else
        echo "The following services are invalid: ${invalid_services[*]}"
        return 1
    fi
}

# Function to validate AWS regions
validate_regions() {
    local input_regions=$1
    local valid_regions=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
    local invalid_regions=()

    IFS=',' read -ra regions <<< "$input_regions"
    for region in "${regions[@]}"; do
        region=$(echo $region | xargs)
        if [[ ! $valid_regions =~ (^|[[:space:]])$region($|[[:space:]]) ]]; then
            invalid_regions+=($region)
        fi
    done

    if [ ${#invalid_regions[@]} -eq 0 ]; then
        echo "All specified regions are valid."
        return 0
    else
        echo "The following regions are invalid: ${invalid_regions[*]}"
        return 1
    fi
}

# Function to validate cron expression
validate_cron() {
    local cron_expr=$1
    if [[ $cron_expr =~ ^cron\([0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+ [0-9*,/-]+ [?*,/-]+ [0-9*,/-]+\)$ ]]; then
        echo "Cron expression is valid."
        return 0
    else
        echo "Invalid cron expression: $cron_expr"
        return 1
    fi
}

# Validate environment variables
if [ -z "$SERVICES" ] || [ -z "$REGIONS" ] || [ -z "$FREQUENCY" ]; then
    echo "Error: SERVICES, REGIONS, and FREQUENCY environment variables must be set."
    exit 1
fi

# Validate services
if ! validate_services "$SERVICES"; then
    echo "Please enter valid service(s)"
    exit 1
fi

# Validate regions
if ! validate_regions "$REGIONS"; then
    echo "Please enter valid region(s)"
    exit 1
fi

# Validate cron expression
if ! validate_cron "$FREQUENCY"; then
    echo "Please enter a valid cron expression"
    exit 1
fi

# Get the DynamoDB table name from the stack outputs
TABLE_NAME=$(aws cloudformation describe-stacks --stack-name ServiceScreenerAutomationStack --query "Stacks[0].Outputs[?OutputKey=='DynamoDBTableName'].OutputValue" --output text)

if [ -z "$TABLE_NAME" ]; then
    echo "Failed to retrieve DynamoDB table name from stack outputs"
    exit 1
fi

echo "DynamoDB table name: $TABLE_NAME"

# Insert initial item into DynamoDB
echo "Inserting initial item into DynamoDB..."
aws dynamodb put-item \
    --table-name $TABLE_NAME \
    --item '{
    "name": {"S": "'"$NAME"'"},
    "services": {"SS": ["'"$(echo $SERVICES | sed "s/,/\",\"/g")"'"]},
    "regions": {"SS": ["'"$(echo $REGIONS | sed "s/,/\",\"/g")"'"]},
    "emails": {"SS": ["'"$(echo $EMAIL_LIST | sed "s/,/\",\"/g")"'"]},
    "frequency": {"S": "'"$FREQUENCY"'"},
    "crossAccounts": {"S": "'"$(echo "$CROSSACCOUNTS" | sed 's/"/\\"/g')"'"}
  }'

echo "Initial item inserted successfully"
