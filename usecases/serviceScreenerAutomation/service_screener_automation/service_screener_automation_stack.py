from aws_cdk import (
    # Duration,
    Stack,
    Duration,
    Size,
    aws_iam as iam,
    RemovalPolicy,
    aws_ec2 as ec2,
    aws_batch as batch,
    aws_ecs as ecs,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_s3 as s3,
    aws_dynamodb as dynamodb,
    aws_lambda as lambda_,
    aws_lambda_event_sources as eventsources,
    aws_sns as sns
    # aws_sqs as sqs,
)
from aws_solutions_constructs.aws_eventbridge_lambda import EventbridgeToLambda, EventbridgeToLambdaProps
from os import path
from constructs import Construct

class ServiceScreenerAutomationStack(Stack):

    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        dirname = path.dirname(__file__)
        super().__init__(scope, construct_id, **kwargs)
        bucket_name = "BucketNameHere1"

        vpc = ec2.Vpc(self, "VPC")
        #S3 Bucket
        bucket = s3.Bucket(self, bucket_name,
            block_public_access=s3.BlockPublicAccess.BLOCK_ALL,
            encryption=s3.BucketEncryption.S3_MANAGED,
            versioned=True,
            removal_policy=RemovalPolicy.RETAIN,
            event_bridge_enabled=True
        )
        #Create Batch
        batch_compute_env = batch.FargateComputeEnvironment(self, "ScreenerEnv",
            vpc=vpc,
            spot=True
        )
        job_role = iam.Role(
            self, "ScreenerBatchRole",
            assumed_by=iam.CompositePrincipal(
                iam.ServicePrincipal("batch.amazonaws.com"),
                iam.ServicePrincipal("ecs.amazonaws.com")
            ),
            description="An example IAM role for Lambda"
        )
        job_role.add_to_policy(iam.PolicyStatement(
            resources=[bucket.bucket_arn],
            actions=["s3:PutObject", "s3:GetObject","s3:DeleteObject"]
        ))
        # Tags.of(batch_compute_env).add("Application", "Screener")
        job_queue = batch.JobQueue(self, "ScreenerQueue",
            priority=1,
            compute_environments=[batch.OrderedComputeEnvironment(
                compute_environment=batch_compute_env,
                order=1
            )
            ]
        )
        #Job Definition
        job_defn = batch.EcsJobDefinition(self, "JobDefn",
            container=batch.EcsFargateContainerDefinition(self, "ScreenerContainer",
                image=ecs.ContainerImage.from_registry("public.ecr.aws/amazonlinux/amazonlinux:latest"),
                memory= Size.mebibytes(2048),
                cpu=1,
                ephemeral_storage_size=Size.gibibytes(30),
                fargate_cpu_architecture=ecs.CpuArchitecture.X86_64,
                fargate_operating_system_family=ecs.OperatingSystemFamily.LINUX
                execution_role=job_role
            )
        )

        #EventBridge Definitions
        ss_rule = events.Rule(self, "ScreenerRule",
            schedule=events.Schedule.cron(minute="0", hour="0", day="3", month="*"),
        )
        ss_rule.add_target(targets.BatchJob(job_queue.job_queue_arn, job_queue, job_defn.job_definition_arn, job_defn,
            # dead_letter_queue=queue,
            event=events.RuleTargetInput.from_object({"SomeParam": "SomeValue"}),
            retry_attempts=2,
            max_event_age=Duration.hours(2)
        ))

        #SNS
        topic = sns.Topic(self, "ScreenerAlertTopic",
            display_name="Email List Topic (Service Screener)"
        )

        #DynamoDB Table
        table = dynamodb.TableV2(self, "ScreenerTable",
            partition_key=dynamodb.Attribute(
                name="id",
                type=dynamodb.AttributeType.STRING
            ),
            dynamo_stream=dynamodb.StreamViewType.NEW_IMAGE
        )
        #Lambda Update Function
        update_fn = lambda_.Function(self, "ScreenerUpdate",
            runtime=lambda_.Runtime.PYTHON_3_12,
            handler="index.lambda_handler",
            code=lambda_.Code.from_asset(path.join(dirname, "update_function"))
        )
        update_fn.add_event_source(eventsources.DynamoEventSource(table,
            starting_position=lambda_.StartingPosition.LATEST,
            filters=[lambda_.FilterCriteria.filter({"event_name": lambda_.FilterRule.is_equal("INSERT")})],
        ))
        #Update function's role
        update_role = update_fn.role
        table.grant_read_data(update_role)
        update_role.add_to_policy(iam.PolicyStatement(
            resources=[ss_rule.rule_arn],
            actions=["events:PutRule"]
        ))
        update_role.add_to_policy(iam.PolicyStatement(
            resources=[topic.topic_arn],
            actions=["sns:GetTopicAttributes", "sns:SetTopicAttributes"]
        ))
        #Findings Function
        event_lambda = EventbridgeToLambda(self, 'eventbridge-lambda',
                lambda_function_props=lambda_.FunctionProps(\
                function_name="ScreenerFindingsAlert",
                runtime=lambda_.Runtime.PYTHON_3_12,
                handler="index.lambda_handler",
                code=lambda_.Code.from_asset(path.join(dirname, "findings_function"))
            ),
            event_rule_props=events.RuleProps(
                event_pattern=events.EventPattern(
                    source=["aws.s3"]
                ),
                
            ),

        )
        findings_role = event_lambda.lambda_function.role
        findings_role.add_to_policy(iam.PolicyStatement(
            resources=[topic.topic_arn],
            actions=["sns:Publish"]
        ))







        # The code that defines your stack goes here

        # example resource
        # queue = sqs.Queue(
        #     self, "ServiceScreenerAutomationQueue",
        #     visibility_timeout=Duration.seconds(300),
        # )
