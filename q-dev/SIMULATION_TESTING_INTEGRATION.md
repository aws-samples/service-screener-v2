# Simulation Testing Integration - Q Developer Guide Update

This document summarizes the integration of the simulation testing framework into the Q Developer documentation.

## What Was Updated

### 1. q-dev/context.md
Added comprehensive section on "Simulation Testing Framework" covering:
- What simulation testing is and why it's important
- Directory structure for simulations
- Available simulations (Glue, SageMaker)
- Simulation workflow (create → test → validate → cleanup)
- Example usage
- Key features (IAM management, cost awareness, self-contained)
- Cost considerations and warnings
- When to use simulation testing
- How to create simulations for new services
- Best practices
- Integration with development workflow

### 2. q-dev/README.md
Added new section "Testing Your Service" with two subsections:

#### Unit Testing
- How to run pytest tests
- What unit tests validate
- Example commands

#### Simulation Testing
- What simulation testing is
- Available simulations
- Step-by-step running instructions
- How to create simulations for new services
- Cost warnings
- Best practices

### 3. Updated Project Structure
Modified the project structure documentation to include:
- `simulation/` directories under each service
- Description of simulation scripts and README

## Key Messages for AI Development

When working with Q Developer CLI, the AI now understands:

1. **Simulation testing is a critical validation step** after implementing security checks
2. **Each service should have a simulation directory** with create/cleanup scripts
3. **Simulations create real AWS resources** with intentional security misconfigurations
4. **Cost awareness is important** - always document costs and cleanup immediately
5. **Simulations validate the entire flow** from discovery to reporting

## Example AI Prompts

After reading the updated context, you can use prompts like:

```
> Create simulation testing scripts for the CloudWatch Logs service that validate 
  the RetentionPolicy and Encryption checks
```

```
> Review the SageMaker simulation scripts and explain what resources are created 
  and which checks they validate
```

```
> I've implemented new RDS security checks. Help me create simulation scripts to 
  validate them with real AWS resources
```

## Benefits

1. **Standardized Testing**: All services follow the same simulation pattern
2. **AI-Assisted Development**: Q Developer can help create simulation scripts
3. **Quality Assurance**: Ensures checks work with real AWS resources
4. **Documentation**: Clear guidance on costs and usage
5. **Maintainability**: Simulations live with the service code they test

## Next Steps

When developing new services with Q Developer:

1. Define checks in reporter.json
2. Implement service and driver classes
3. **Create simulation scripts** (new step!)
4. Run unit tests
5. **Run simulation tests** (new step!)
6. Validate results in HTML report
7. Iterate until all checks work correctly

## Files Modified

- `service-screener-v2/q-dev/context.md` - Added simulation testing section
- `service-screener-v2/q-dev/README.md` - Added testing section with simulation instructions

## Files Referenced

- `service-screener-v2/SIMULATION_TESTING.md` - Master simulation documentation
- `service-screener-v2/services/glue/simulation/` - Example simulation
- `service-screener-v2/services/sagemaker/simulation/` - Example simulation

## Template for New Simulations

When creating simulations for new services, follow this structure:

```
services/{SERVICE_NAME}/simulation/
├── create_test_resources.sh    # Creates IAM roles + insecure resources
├── cleanup_test_resources.sh   # Removes all resources + IAM roles
└── README.md                   # Documents resources, costs, usage
```

Each script should:
- Handle errors gracefully
- Document which checks are validated
- Include cost estimates
- Use `test-` prefix for resources
- Wait for IAM role propagation
- Provide clear success/failure messages
