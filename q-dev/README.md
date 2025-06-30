# Development with Q CLI

This guide shows how to use Amazon Q Developer CLI to efficiently develop and maintain the Service Screener codebase using pre-built prompt templates.

## Table of Contents
1. [Initializing Chat Session](#initializing-chat-session) (DO THIS IN EVERY NEW SESSION)
2. [Using Prompt Templates](#using-prompt-templates)
    - [Defining Service Reporter Configurations](#defining-service-reporter-configurations)
    - [Creating a New Service](#creating-a-new-service)
    - [Extending an Existing Service](#extending-an-existing-service)


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

