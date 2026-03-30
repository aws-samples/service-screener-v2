#!/bin/bash
# Script to create intentionally insecure Glue resources for testing
# These resources will trigger FAIL (-1) status in Service Screener checks

REGION="us-east-1"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo "Creating insecure Glue test resources in region: $REGION"
echo "Account ID: $ACCOUNT_ID"
echo "================================================"

# ============================================
# IAM ROLE SETUP
# ============================================

echo ""
echo "Setting up IAM role for Glue..."

aws iam create-role \
  --role-name AWSGlueServiceRole-TestRole \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "glue.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }' \
  2>/dev/null || echo "  ⚠️  Role may already exist"

aws iam attach-role-policy \
  --role-name AWSGlueServiceRole-TestRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole \
  2>/dev/null || true

echo "  ✓ Glue role ready"
echo "  ⏳ Waiting 10 seconds for IAM role to propagate..."
sleep 10

# ============================================
# GLUE RESOURCES
# ============================================

echo ""
echo "1. Creating Glue Job WITHOUT security configuration and bookmarks disabled..."
aws glue create-job \
  --region $REGION \
  --name test-insecure-glue-job \
  --role arn:aws:iam::${ACCOUNT_ID}:role/AWSGlueServiceRole-TestRole \
  --command Name=glueetl,ScriptLocation=s3://aws-glue-scripts-${ACCOUNT_ID}-${REGION}/test.py,PythonVersion=3 \
  --default-arguments '{"--TempDir":"s3://aws-glue-temporary-'${ACCOUNT_ID}'-'${REGION}'/temp","--job-bookmark-option":"job-bookmark-disable"}' \
  --max-retries 0 \
  --timeout 60 \
  --glue-version "3.0" \
  2>/dev/null || echo "  ⚠️  Job may already exist"

echo "  ✓ Created job without SecurityConfiguration and bookmarks disabled"
echo "    Validates: JobS3Encryption, JobCloudWatchLogsEncryption, JobBookmarkEncryption, JobLoggingEnabled, JobBookmarkEnabled"

echo ""
echo "2. Creating Glue Job with OLD Glue version..."
aws glue create-job \
  --region $REGION \
  --name test-old-version-glue-job \
  --role arn:aws:iam::${ACCOUNT_ID}:role/AWSGlueServiceRole-TestRole \
  --command Name=glueetl,ScriptLocation=s3://aws-glue-scripts-${ACCOUNT_ID}-${REGION}/test.py,PythonVersion=3 \
  --default-arguments '{"--TempDir":"s3://aws-glue-temporary-'${ACCOUNT_ID}'-'${REGION}'/temp"}' \
  --max-retries 0 \
  --timeout 60 \
  --glue-version "2.0" \
  2>/dev/null || echo "  ⚠️  Job may already exist"

echo "  ✓ Created job with old Glue version (2.0)"
echo "    Validates: GlueVersionCurrent"

echo ""
echo "3. Creating Glue Connection WITHOUT SSL..."
aws glue create-connection \
  --region $REGION \
  --connection-input '{
    "Name": "test-insecure-connection",
    "ConnectionType": "JDBC",
    "ConnectionProperties": {
      "JDBC_ENFORCE_SSL": "false",
      "JDBC_CONNECTION_URL": "jdbc:mysql://test-host:3306/testdb",
      "USERNAME": "testuser",
      "PASSWORD": "testpass"
    }
  }' \
  2>/dev/null || echo "  ⚠️  Connection may already exist"

echo "  ✓ Created connection with SSL disabled"
echo "    Validates: SslEnabled"

echo ""
echo "4. Creating Glue Crawler WITHOUT schedule..."
aws glue create-crawler \
  --region $REGION \
  --name test-unscheduled-crawler \
  --role arn:aws:iam::${ACCOUNT_ID}:role/AWSGlueServiceRole-TestRole \
  --database-name test_ml_database \
  --targets S3Targets=[{Path=s3://aws-glue-temporary-${ACCOUNT_ID}-${REGION}/test/}] \
  2>/dev/null || echo "  ⚠️  Crawler may already exist"

echo "  ✓ Created crawler without schedule"
echo "    Validates: CrawlerScheduleConfigured"

echo ""
echo "5. Creating Glue Dev Endpoint WITHOUT security configuration..."
aws glue create-dev-endpoint \
  --region $REGION \
  --endpoint-name test-insecure-dev-endpoint \
  --role-arn arn:aws:iam::${ACCOUNT_ID}:role/AWSGlueServiceRole-TestRole \
  --glue-version "3.0" \
  --number-of-nodes 2 \
  2>/dev/null || echo "  ⚠️  Dev endpoint may already exist"

echo "  ✓ Created dev endpoint without SecurityConfiguration"
echo "    Validates: DevEndpointCloudWatchLogsEncryption, DevEndpointBookmarkEncryption, DevEndpointS3Encryption"
echo "    ⚠️  WARNING: Dev endpoints cost ~$0.44/hour - remember to cleanup!"

echo ""
echo "6. Creating Glue ML Transform WITHOUT encryption..."
# First create a sample database and table for the ML transform
aws glue create-database \
  --region $REGION \
  --database-input Name=test_ml_database \
  2>/dev/null || echo "  ⚠️  Database may already exist"

aws glue create-table \
  --region $REGION \
  --database-name test_ml_database \
  --table-input '{
    "Name": "test_ml_table",
    "StorageDescriptor": {
      "Columns": [
        {"Name": "id", "Type": "string"},
        {"Name": "name", "Type": "string"}
      ],
      "Location": "s3://aws-glue-temporary-'${ACCOUNT_ID}'-'${REGION}'/test/",
      "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
      "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
      "SerdeInfo": {
        "SerializationLibrary": "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
      }
    }
  }' \
  2>/dev/null || echo "  ⚠️  Table may already exist"

aws glue create-ml-transform \
  --region $REGION \
  --name test-insecure-ml-transform \
  --role arn:aws:iam::${ACCOUNT_ID}:role/AWSGlueServiceRole-TestRole \
  --input-record-tables DatabaseName=test_ml_database,TableName=test_ml_table \
  --parameters TransformType=FIND_MATCHES,FindMatchesParameters={PrimaryKeyColumnName=id} \
  2>/dev/null || echo "  ⚠️  ML Transform may already exist"

echo "  ✓ Created ML transform without encryption at rest"
echo "    Validates: MLTransformEncryptionAtRest"

echo ""
echo "================================================"
echo "✅ Glue test resources created successfully!"
echo ""
echo "Resources created:"
echo "  - 2 Glue Jobs (no security config, old version, bookmarks disabled)"
echo "  - 1 Glue Connection (SSL disabled)"
echo "  - 1 Glue Crawler (no schedule)"
echo "  - 1 Glue Dev Endpoint (no security config) ⚠️  COSTS MONEY"
echo "  - 1 Glue ML Transform (no encryption)"
echo "  - 1 Glue Database + Table (supporting resources)"
echo ""
echo "Validates 12 checks (80% coverage):"
echo "  ✓ JobS3Encryption"
echo "  ✓ JobCloudWatchLogsEncryption"
echo "  ✓ JobBookmarkEncryption"
echo "  ✓ JobLoggingEnabled"
echo "  ✓ JobBookmarkEnabled"
echo "  ✓ GlueVersionCurrent"
echo "  ✓ SslEnabled"
echo "  ✓ CrawlerScheduleConfigured"
echo "  ✓ DevEndpointCloudWatchLogsEncryption"
echo "  ✓ DevEndpointBookmarkEncryption"
echo "  ✓ DevEndpointS3Encryption"
echo "  ✓ MLTransformEncryptionAtRest"
echo ""
echo "Note: 3 Data Catalog checks require account-level configuration:"
echo "  - ConnectionPasswordEncryption"
echo "  - MetadataEncryption"
echo "  - PublicAccessibility"
echo ""
echo "To cleanup these resources, run:"
echo "  ./cleanup_test_resources.sh"
