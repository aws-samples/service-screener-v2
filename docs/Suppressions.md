# Using Suppressions in Service Screener

Service Screener allows you to suppress specific findings using a JSON suppression file. This is useful when you have known exceptions or when certain findings are not relevant to your environment.

## Basic Usage

To use suppressions, provide the path to your suppression file when running Service Screener:

```bash
screener --regions ap-southeast-1 --suppress_file ./suppressions.json
```

## Suppression File Format

The suppression file uses a simple JSON format:

```json
{
 "metadata": {
   "version": "1.0",
   "description": "Your suppression description"
 },
 "suppressions": [
   {
     "service": "s3",
     "rule": "BucketReplication"
   },
   {
     "service": "s3",
     "rule": "BucketLifecycle"
   },
   {
     "service": "rds",
     "rule": "BucketVersioning",
     "resource_id": ["Bucket::sample-bucket-name"]
   }
 ]
}
```

### Structure

- **metadata**: Contains information about the suppression file
  - **version**: Version of the suppression file format
  - **description**: Description of the suppression file

- **suppressions**: Array of suppression rules
  - **service**: AWS service name (e.g., 's3', 'rds')
  - **rule**: Rule identifier to suppress
  - **resource_id** (optional): Array of specific resource identifiers to suppress. If not provided, the rule is suppressed for all resources of that service.

## Suppression Types

### Service-Level Suppressions

To suppress a rule for all resources of a service:

```json
{
  "service": "s3",
  "rule": "BucketReplication"
}
```

### Resource-Specific Suppressions

To suppress a rule only for specific resources:

```json
{
  "service": "rds",
  "rule": "BackupRetention",
  "resource_id": ["db-instance-1", "db-instance-2"]
}
```
