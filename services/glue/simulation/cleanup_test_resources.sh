#!/bin/bash
# Script to cleanup Glue test resources

REGION="us-east-1"

echo "Cleaning up Glue test resources in region: $REGION"
echo "================================================"

echo ""
echo "1. Deleting Glue Jobs..."
aws glue delete-job \
  --region $REGION \
  --job-name test-insecure-glue-job \
  2>/dev/null && echo "  ✓ Deleted test-insecure-glue-job" || echo "  ⚠️  test-insecure-glue-job not found"

aws glue delete-job \
  --region $REGION \
  --job-name test-old-version-glue-job \
  2>/dev/null && echo "  ✓ Deleted test-old-version-glue-job" || echo "  ⚠️  test-old-version-glue-job not found"

echo ""
echo "2. Deleting Glue Connection..."
aws glue delete-connection \
  --region $REGION \
  --connection-name test-insecure-connection \
  2>/dev/null && echo "  ✓ Deleted" || echo "  ⚠️  Not found or already deleted"

echo ""
echo "3. Deleting Glue Crawler..."
aws glue delete-crawler \
  --region $REGION \
  --name test-unscheduled-crawler \
  2>/dev/null && echo "  ✓ Deleted" || echo "  ⚠️  Not found or already deleted"

echo ""
echo "4. Deleting Glue Dev Endpoint..."
aws glue delete-dev-endpoint \
  --region $REGION \
  --endpoint-name test-insecure-dev-endpoint \
  2>/dev/null && echo "  ✓ Deleted" || echo "  ⚠️  Not found or already deleted"

echo ""
echo "5. Deleting Glue ML Transform..."
TRANSFORM_ID=$(aws glue get-ml-transforms \
  --region $REGION \
  --filter Name=test-insecure-ml-transform \
  --query 'Transforms[0].TransformId' \
  --output text 2>/dev/null)

if [ "$TRANSFORM_ID" != "None" ] && [ -n "$TRANSFORM_ID" ]; then
  aws glue delete-ml-transform \
    --region $REGION \
    --transform-id $TRANSFORM_ID \
    2>/dev/null && echo "  ✓ Deleted" || echo "  ⚠️  Not found or already deleted"
else
  echo "  ⚠️  ML Transform not found"
fi

echo ""
echo "6. Deleting Glue test database and table..."
aws glue delete-table \
  --region $REGION \
  --database-name test_ml_database \
  --name test_ml_table \
  2>/dev/null && echo "  ✓ Deleted table" || echo "  ⚠️  Table not found"

aws glue delete-database \
  --region $REGION \
  --name test_ml_database \
  2>/dev/null && echo "  ✓ Deleted database" || echo "  ⚠️  Database not found"

echo ""
echo "7. Deleting IAM role..."
aws iam detach-role-policy \
  --role-name AWSGlueServiceRole-TestRole \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole \
  2>/dev/null || echo "  ⚠️  Policy not attached"

aws iam delete-role \
  --role-name AWSGlueServiceRole-TestRole \
  2>/dev/null && echo "  ✓ Deleted IAM role" || echo "  ⚠️  Role not found"

echo ""
echo "================================================"
echo "✅ Glue cleanup complete!"
