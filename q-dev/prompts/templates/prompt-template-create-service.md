IMPORTANT: Do not execute the following instructions unless specifically instructed to.

You are an expert Python developer specializing in AWS SDK (boto3) and Service Screener architecture. Generate a complete Service Screener service implementation based on provided reporter configuration.

CONTEXT:
You have already read ./docs/DevelopmentGuide.md which contains all architectural patterns, base classes, naming conventions, and implementation requirements for Service Screener services.

INPUT PARAMETERS:
Service Name: `{SERVICE_NAME}`

Reporter Configuration: 
`{REPORTER_JSON_CONTENT}`

TASK:
Create a complete, production-ready Service Screener service implementation including main service class, driver class, and all check methods based on the provided reporter configuration.

IMPLEMENTATION REQUIREMENTS:
1. Main Service Class: services/[service_name]/[ServiceName].py
   - Inherit from Service base class
   - Implement getResources() with pagination and tag filtering
   - Implement advise() method for orchestration
   - Use self.ssBoto.client() for AWS clients
   - Handle errors with try/catch blocks
   - Use _pi() for progress indicators

2. Driver Class: services/[service_name]/drivers/[ResourceType]Driver.py
   - Inherit from Evaluator base class
   - Set self._resourceName to unique resource identifier
   - Use self.addII() to store resource metadata
   - Implement one _check method per reporter config entry
   - Method names: _check + camelCase version of reporter key
   - Results format: self.results['CheckName'] = [status, value]
   - Status codes: -1 (attention), 0 (info), 1 (pass)

3. Check Method Implementation:
   - Convert reporter config keys to _check method names
   - Map criticality to status codes (High/Medium → -1 when failing, Low → 0 for info)
   - Use appropriate boto3 API calls based on service
   - Handle AWS exceptions (AccessDenied, ResourceNotFound, etc.)
   - Provide descriptive result values

4. Code Quality:
   - Include docstrings for classes and methods
   - Use clear variable names and logical organization
   - Implement comprehensive error handling
   - Minimize API calls through efficient patterns
   - Follow existing Service Screener conventions

DELIVERABLES:
Generate the following files with complete implementations:
1. services/[service_name]/[ServiceName].py - Main service class
2. services/[service_name]/drivers/[ResourceType]Driver.py - Driver implementation
3. Validation that all reporter config checks are implemented as methods
4. Do not create a summary document of the resulting implementation
5. Upon completion, delete any validation script or files that is not part of the service (outside of the services/[service_name] folder), so as not to leave any residual

TECHNICAL SPECIFICATIONS:
- Use correct boto3 service names for client initialization
- Implement pagination for services with large result sets
- Support tag-based filtering using self.resourceHasTags()
- Handle regional vs global services appropriately
- Include proper import statements
- Follow PascalCase for class names, camelCase for method names
- Use self.bConfig for boto3 client configuration

VALIDATION CHECKLIST:
Ensure all check methods from reporter config are implemented, method names follow _check + camelCase convention, results use [status, value] format, error handling covers AWS exceptions, resource discovery includes pagination, tag filtering implemented where applicable, progress indicators used appropriately, code follows Service Screener patterns, imports are correct, resource identification is unique.

Generate complete working code that handles real-world scenarios including error conditions, edge cases, and various resource configurations. The implementation should be production-ready and follow all established Service Screener architectural patterns.
