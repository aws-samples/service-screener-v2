IMPORTANT: Do not execute the following instructions unless specifically instructed to.

You are an expert Python developer specializing in AWS SDK (boto3) and Service Screener architecture. Update an existing Service Screener service implementation by adding new checks based on provided reporter configuration.

CONTEXT:
You have already read ./docs/DevelopmentGuide.md which contains all architectural patterns, base classes, naming conventions, and implementation requirements for Service Screener services.

INPUT PARAMETERS:
Existing Service Name: `{SERVICE_NAME}`

New Reporter Configuration to Add: 
`{NEW_REPORTER_JSON_CONTENT}`

TASK:
Update the existing Service Screener service implementation by adding new check methods and updating the reporter configuration. DO NOT remove or modify existing checks - only add new ones.

PRE-UPDATE ANALYSIS:
1. Read the existing service files:
   - services/[service_name]/[ServiceName].py
   - services/[service_name]/drivers/[ResourceType]Driver.py  
   - services/[service_name]/[service_name].reporter.json

2. Compare existing reporter config with new reporter config:
   - Identify checks that already exist (same name or similar functionality)
   - Identify truly new checks that need to be added
   - For overlapping checks, PRESERVE the existing implementation
   - Only add checks that don't already exist

3. Determine which driver classes need updates based on new checks

UPDATE REQUIREMENTS:
1. Reporter Configuration Update:
   - Merge new reporter config with existing config
   - Preserve all existing check configurations
   - Only add new checks that don't conflict with existing ones
   - If a check name exists in both configs, keep the existing one
   - If similar functionality exists under different names, keep existing and skip new

2. Driver Class Updates:
   - Add new _check methods only for truly new checks
   - DO NOT modify existing _check methods
   - Follow existing code patterns and style in the file
   - Maintain consistency with existing method implementations
   - Use appropriate boto3 API calls based on service and existing patterns

3. Service Class Updates (if needed):
   - Only update if new checks require additional AWS clients or resources
   - Preserve all existing functionality
   - Add new client initialization if required for new checks
   - Update resource discovery only if new resource types are needed

4. Implementation Standards:
   - New check methods: _check + camelCase version of reporter key
   - Results format: self.results['CheckName'] = [status, value]
   - Status codes: -1 (attention), 0 (info), 1 (pass)
   - Handle AWS exceptions (AccessDenied, ResourceNotFound, etc.)
   - Include docstrings for new methods
   - Follow existing error handling patterns

CONFLICT RESOLUTION:
- If new check name matches existing check name: Skip the new check
- If new check functionality overlaps with existing check: Skip the new check
- If uncertain about overlap: Err on the side of preserving existing checks
- Document any skipped checks in comments

DELIVERABLES:
1. Updated services/[service_name]/[service_name].reporter.json - Merged configuration
2. Updated services/[service_name]/drivers/[ResourceType]Driver.py - With new check methods
3. Updated services/[service_name]/[ServiceName].py - Only if new clients/resources needed
4. Summary comment in each updated file listing what was added
5. Do not create separate validation or summary files
6. Upon completion, delete any temporary files created during the process

TECHNICAL SPECIFICATIONS:
- Preserve all existing imports and add new ones only if needed
- Use existing boto3 client patterns for new API calls
- Follow existing error handling patterns
- Maintain existing code style and formatting
- Use existing progress indicator patterns
- Follow existing resource identification patterns

VALIDATION CHECKLIST:
Before making changes: Read and understand existing implementation, identify existing checks and their functionality, compare with new checks to avoid duplicates, plan minimal changes needed.

After making changes: All existing checks remain unchanged, new checks follow naming conventions, new checks use [status, value] format, error handling matches existing patterns, no duplicate functionality added, reporter config properly merged, imports updated only if necessary.

IMPORTANT CONSTRAINTS:
- NEVER remove or modify existing check methods
- NEVER modify existing reporter configuration entries
- NEVER change existing resource discovery logic unless absolutely necessary
- ONLY add new functionality, never replace existing functionality
- If in doubt about whether a check already exists, DO NOT add the new check

Generate updated code that seamlessly integrates new checks with existing implementation while preserving all current functionality. The update should be additive only and maintain backward compatibility.
