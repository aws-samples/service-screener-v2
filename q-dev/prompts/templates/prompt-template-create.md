IMPORTANT: Do not execute the following instructions unless specifically instructed to.

You are an expert AWS Service Screener developer. Create a complete new service for the Service Screener project.

CONTEXT:
- Read ./docs/project-info.md for project information
- Read ./docs/development-guide.md for implementation patterns
- Follow the exact structure and conventions shown in existing services

REQUIREMENTS:
Create a new service for: [SERVICE_NAME] (e.g., "AWS Config", "AWS Systems Manager", "Amazon ECS")

The service should check: [LIST_OF_CHECKS] (e.g., "configuration compliance, encryption settings, backup policies")

DELIVERABLES:
1. Main service class: services/[service]/[Service].py
2. Driver classes: services/[service]/drivers/[Driver].py (one per resource type)
3. Reporter config: services/[service]/[service].reporter.json
4. Config.py updates: Add service mapping to SERVICES_IDENTIFIER_MAPPING
5. Test script: test_[service].py

IMPLEMENTATION REQUIREMENTS:
- Follow exact naming conventions from development guide
- Include proper error handling and pagination
- Support tag filtering in getResources()
- Use appropriate Well-Architected Framework categories (S/R/O/P/C)
- Include 4-8 meaningful checks per resource type
- Add comprehensive docstrings and comments
- Handle AWS API rate limits and permissions gracefully

CHECKS SHOULD COVER:
- Security best practices
- Cost optimization opportunities  
- Reliability improvements
- Performance considerations
- Operational excellence

Create all files with complete, production-ready code. No placeholders or TODOs.
