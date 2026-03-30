# Development with Q CLI

This guide shows how to use Amazon Q Developer CLI to efficiently develop and maintain the Service Screener codebase using pre-built prompt templates.

## Table of Contents
1. [Initializing Chat Session](#initializing-chat-session) (DO THIS IN EVERY NEW SESSION)
2. [Using Prompt Templates](#using-prompt-templates)
    - [Defining Service Reporter Configurations](#defining-service-reporter-configurations)
    - [Creating a New Service](#creating-a-new-service)
    - [Extending an Existing Service](#extending-an-existing-service)
3. [Testing Your Service](#testing-your-service)
    - [Unit Testing](#unit-testing)
    - [Simulation Testing](#simulation-testing)


## Initializing Chat Session 
**DO THIS IN EVERY NEW SESSION**

Open terminal in the root of this project and start a Q Developer chat session:

```bash
q chat
```

Then initialize the AI with project context:

```
> Read ./q-dev/context.md and ./docs/DevelopmentGuide.md for information on this project
```

## Using Prompt Templates

The `./q-dev/prompts/templates/` folder contains ready-to-use prompt templates for common development tasks. Simply copy the template content and customize the placeholders.

### Available Templates

1. **prompt-template-define.md** - Define comprehensive checks for a service
2. **prompt-template-create.md** - Create a complete new AWS service
3. **prompt-template-update.md** - Update existing services with new checks

### Defining Service Reporter Configurations

Use the **define template** to create a service reporter configuration JSON file:

**Step 1:** Make a copy of the template file
```
cp ./q-dev/prompts/templates/prompt-template-define.md ./prompt-template-define-{yourname}.md
```

**Step 2:** Edit the template file in `./prompt-template-define-{yourname}.md` to customize the placeholders:
- `{AWS_SERVICE_NAME}`: The AWS Service that you want to generate the reporter for, example: SQS.

**Step 3:** Execute the instructions:
```
> Execute the instructions in ./prompt-template-define-{yourname}.md
```

### Creating a New Service

Use the **create template** for implementing entirely new AWS services:

**Step 1:** Make a copy of the template file
```
cp ./q-dev/prompts/templates/prompt-template-create-service.md ./prompt-template-create-service-{yourname}.md
```

**Step 2:** Edit the template file in `./prompt-template-create-service-{yourname}.md` to customize the placeholders:
- `{SERVICE_NAME}`: The AWS Service that you want to generate the service for, example: SQS.
- `{REPORTER_JSON_CONTENT}`: The entire content of the reporter.json in which you want to generate a service for.

**Step 3:** Execute the instructions:
```
> Execute the instructions in ./prompt-template-create-service-{yourname}.md
```

### Extending an Existing Service

Use the **extend template** for adding new assessments to an existing AWS services:

**Step 1:** Make a copy of the template file
```
cp ./q-dev/prompts/templates/prompt-template-extend-service.md ./prompt-template-extend-service-{yourname}.md
```

**Step 2:** Edit the template file in `./prompt-template-extend-service-{yourname}.md` to customize the placeholders:
- `{SERVICE_NAME}`: The AWS Service that you want to generate the service for, example: SQS.
- `{REPORTER_JSON_CONTENT}`: The entire content of the reporter.json in which you want to extend a service for.

**Step 3:** Execute the instructions:
```
> Execute the instructions in ./prompt-template-extend-service-{yourname}.md
```

## Testing Your Service

After creating or extending a service, it's important to validate that your checks work correctly.

### Unit Testing

Run the pytest unit tests to verify driver logic:

```bash
# Run all tests
pytest tests/

# Run tests for a specific service
pytest tests/test_glue_*.py
pytest tests/test_sagemaker_*.py
```

Unit tests validate:
- Check methods execute without errors
- Results follow the correct format `[status, value]`
- Edge cases are handled properly
- Mock AWS API responses work as expected

### Simulation Testing

Simulation testing validates checks with real AWS resources. This is the most comprehensive way to ensure your checks work in production.

**What is Simulation Testing?**

Simulation testing creates intentionally insecure AWS resources that should trigger FAIL (-1) status in your checks. This validates the entire flow:
1. Service discovery finds the resources
2. Driver classes evaluate configurations correctly
3. Checks identify security misconfigurations
4. Reporter displays findings properly

**Available Simulations:**
- **Glue**: `services/glue/simulation/`
- **SageMaker**: `services/sagemaker/simulation/`

**Running a Simulation:**

```bash
# Example: Test SageMaker checks
cd services/sagemaker/simulation

# 1. Create insecure test resources
./create_test_resources.sh

# 2. Run Service Screener
cd ../../..
python3 main.py --regions us-east-1 --services sagemaker --beta 1 --sequential 1

# 3. Review the HTML report to verify checks show FAIL status

# 4. Cleanup resources (IMPORTANT to avoid costs!)
cd services/sagemaker/simulation
./cleanup_test_resources.sh
```

**Creating Simulations for New Services:**

When adding a new service, create a `simulation/` directory with:

1. `create_test_resources.sh` - Creates insecure AWS resources
2. `cleanup_test_resources.sh` - Removes all test resources
3. `README.md` - Documents resources, costs, and usage

See `../SIMULATION_TESTING.md` for detailed documentation and examples.

**Cost Warning:** ⚠️ Simulation testing creates real AWS resources that may incur costs. Always run cleanup scripts immediately after testing. Most simulations cost < $0.50 per run, but some resources (like Glue Dev Endpoints) can cost ~$0.44/hour.

**Best Practices:**
- Use a dedicated test AWS account
- Run cleanup scripts immediately after testing
- Document estimated costs in simulation README
- Prefix test resources with `test-` for easy identification
- Handle IAM role creation and cleanup automatically

