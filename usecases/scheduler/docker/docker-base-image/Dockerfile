# Use a base image with the necessary dependencies
FROM --platform=linux/x86-64 python:3.12-slim 

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl unzip git jq && \
    rm -rf /var/lib/apt/lists/*

# Install AWS CLI
RUN curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip" && \
    unzip awscliv2.zip && \
    ./aws/install && \
    rm -rf awscliv2.zip aws

RUN aws --version

# Set the working directory
WORKDIR /app

# Copy the application code
COPY . .

# Create a virtual environment and install dependencies
# RUN python3 -m venv .
RUN python3 -m pip install --upgrade pip \
    && rm -rf service-screener-v2 \
    && git clone https://github.com/aws-samples/service-screener-v2.git \
    && cd service-screener-v2 \
    && pip install -r requirements.txt 