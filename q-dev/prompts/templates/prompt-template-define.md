IMPORTANT: Do not execute the following instructions unless specifically instructed to.

You are an AWS security and best practices expert. 
Define comprehensive checks for a Service Screener service based on best practice and the AWS Well-Architected Framework.

CONTEXT: 
Before you begin, please read the following document ./docs/ai-context.md if you haven't done so already. 
This will give you an understanding of Service Screener.

REQUIREMENTS:
Define checks for service: [AWS_SERVICE_NAME]

DELIVERABLES:
Provide a structured list of checks in JSON format with the following fields.
1. CHECK_NAME: Brief descriptive name
2. CATEGORY: S(ecurity)/R(eliability)/O(perational)/P(erformance)/C(ost)
3. CRITICALITY: H(igh)/M(edium)/L(ow)
4. DESCRIPTION: What the check evaluates
5. RATIONALE: Why this matters (business impact)
6. AWS_APIS: Which APIs to call
7. LOGIC: How to determine pass/fail
8. REFERENCES: AWS documentation links

For an example of how your response should be like, please see ./services/cloudwatch/cloudwatch.reporter.json

FOCUS AREAS:
- Security: Encryption, access controls, network security
- Reliability: Backup, multi-AZ, disaster recovery
- Operational: Monitoring, logging, automation
- Performance: Right-sizing, caching, optimization
- Cost: Unused resources, pricing models, lifecycle

Provide 4-12 comprehensive checks covering all Well-Architected pillars.

Save your JSON response in the file ./docs/generated_reporter.json. You may overwrite if the file already exist.
