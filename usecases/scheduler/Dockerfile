# Use a base image with the necessary dependencies
FROM python:3.9-slim

# Install dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    unzip

RUN yum install -y glibc


# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" \
    && unzip awscliv2.zip \
    && ./aws/install \
    && rm -rf awscliv2.zip aws

# Set the working directory
WORKDIR /app

# Copy the application code
COPY . .

# Create a virtual environment and install dependencies
RUN python3 -m venv .
RUN . bin/activate \
    && python3 -m pip install --upgrade pip \
    && rm -rf service-screener-v2 \
    && git clone https://github.com/aws-samples/service-screener-v2.git \
    && cd service-screener-v2 \
    && pip install -r requirements.txt

# Set the alias
RUN echo "alias screener='python3 \$(pwd)/main.py'" >> ~/.bashrc

# Run the screener command
# RUN bash -c "source ~/.bashrc && screener --regions us-east-1"

# Define the ARG for the region
ARG REGION
RUN REGION=$(aws dynamodb get-item \
--table-name ss-parameters \
--key '{"name": {"S": "test-1"}' \
--projection-expression "region" --query "Item.region.S" --output text)

# Set the command to run the application
CMD ["bash", "-c", "source ~/.bashrc && screener --regions $REGION"]

# Define the ARG for S3 bucket
ARG ACCOUNT_ID
RUN ACCOUNT_ID=$(aws sts get-caller-identity --query "Account" --output text) \
    && echo "AWS Account ID: $ACCOUNT_ID"

# Get the current date and save it as a variable
ARG CURRENT_DATE
RUN CURRENT_DATE=$(date +"%Y-%m-%d") \
    && echo "Current Date: $CURRENT_DATE"

# Upload the output.zip file to S3 with file name as current date
RUN aws s3 cp ~/service-screener-v2/output.zip s3://service-screener-results-$ACCOUNT_ID/$CURRENT_DATE.zip


