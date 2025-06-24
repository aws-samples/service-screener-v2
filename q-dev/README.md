# Development with Q CLI

This guide shows how to use Amazon Q Developer CLI to efficiently develop and maintain the Service Screener codebase using pre-built prompt templates.

## Initializing Chat Session

Open terminal in the root of this project and start a Q Developer chat session:

```bash
q chat
```

Then initialize the AI with project context:

```
> Read ./q-dev/context.md and ./docs/development-guide.md for information on this project
```

## Using Prompt Templates

The `./q-dev/prompts/templates/` folder contains ready-to-use prompt templates for common development tasks. Simply copy the template content and customize the placeholders.

### Available Templates

1. **prompt-template-define.md** - Define comprehensive checks for a service
2. **prompt-template-create.md** - Create a complete new AWS service
3. **prompt-template-update.md** - Update existing services with new checks

## Development Workflows

### 1. Defining Reporter Configurations for a Service

Use the **define template** to create a service reporter configuration JSON file:

**Step 1:** Make a copy of the template file
```
cp ./q-dev/prompts/templates/prompt-template-define.md ./prompt-template-define-{yourname}.md
```

**Step 2:** Edit the template file in `./prompt-template-define-{yourname}.md` to customize the placeholders:
- `[AWS_SERVICE_NAME]`: The AWS Service that you want to generate the reporter for, example: SQS.

**Step 3:** Execute the instructions:
```
> Execute the instructions in ./prompt-template-define-{yourname}.md
```

### 2. Creating a New Service

Use the **create template** for implementing entirely new AWS services:

**Step 1:** Make a copy of the template file
```
cp ./q-dev/prompts/templates/prompt-template-create.md ./prompt-template-create-{yourname}.md
```

**Step 2:** Edit the template file in `./prompt-template-create-{yourname}.md` to customize the placeholders:
- `[REPORTER_JSON]`: The entire content of the reporter.json in which you want to generate a service for.

**Step 3:** Execute the instructions:
```
> Execute the instructions in ./prompt-template-create-{yourname}.md
```

### 3. Updating an Existing Service

Use the **update template** for implementing entirely new AWS services:

**Step 1:** Make a copy of the template file
```
cp ./q-dev/prompts/templates/prompt-template-update.md ./prompt-template-update-{yourname}.md
```

**Step 2:** Edit the template file in `./prompt-template-update-{yourname}.md` to customize the placeholders:
- `[SERVICE_NAME]`: The existing service folder name.
- `[REPORTER_JSON]`: The entire content of the reporter.json.

**Step 3:** Execute the instructions:
```
> Execute the instructions in ./prompt-template-update-{yourname}.md
```

