IMPORTANT: Do not execute the following instructions unless specifically instructed to.

You are an expert AWS Service Screener developer. Update an existing service to add new checks.

CONTEXT:
- Read ./docs/project-info.md for project information
- Read ./docs/development-guide.md for implementation patterns
- Examine existing service structure in services/[SERVICE_NAME]/

REQUIREMENTS:
Update service: [SERVICE_NAME]
Add these new checks: [LIST_OF_NEW_CHECKS]
Target resource type: [RESOURCE_TYPE] (if adding to existing driver) OR create new driver for: [NEW_RESOURCE_TYPE]

DELIVERABLES:
1. Updated driver class with new _check methods
2. Updated reporter JSON with new check definitions
3. Updated Config.py if adding new resource types
4. Updated test script to cover new checks

IMPLEMENTATION REQUIREMENTS:
- Follow existing code patterns in the service
- Maintain consistency with existing check naming
- Use same error handling patterns as existing checks
- Add appropriate Well-Architected Framework categories
- Include proper documentation and references
- Ensure new checks don't conflict with existing ones

ANALYSIS FIRST:
1. Examine existing service structure
2. Identify where new checks should be added
3. Determine if new driver classes are needed
4. Check for any dependencies or conflicts

Create complete, tested code that integrates seamlessly with existing service.
