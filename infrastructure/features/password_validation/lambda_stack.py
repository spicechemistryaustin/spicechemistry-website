from aws_cdk import (
    Stack,
    Duration,
    RemovalPolicy,
    aws_lambda as _lambda,
    aws_apigateway as apigateway,
    aws_dynamodb as dynamodb,
    aws_iam as iam,
    aws_logs as logs,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cw_actions,
    aws_sns as sns
)
from constructs import Construct


class PasswordValidationLambdaStack(Stack):
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # DynamoDB table for user security profiles and events
        self.users_table = dynamodb.Table(
            self, "UsersTable",
            table_name="Users",
            partition_key=dynamodb.Attribute(
                name="PK",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="SK", 
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            removal_policy=RemovalPolicy.DESTROY,  # Use RETAIN for production
            point_in_time_recovery=True,
            time_to_live_attribute="ttl",
            stream=dynamodb.StreamViewType.NEW_AND_OLD_IMAGES
        )
        
        # Add GSI for querying by timestamp
        self.users_table.add_global_secondary_index(
            index_name="TimestampIndex",
            partition_key=dynamodb.Attribute(
                name="timestamp",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.ALL
        )
        
        # Lambda execution role
        lambda_role = iam.Role(
            self, "PasswordValidationLambdaRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            managed_policies=[
                iam.ManagedPolicy.from_aws_managed_policy_name(
                    "service-role/AWSLambdaBasicExecutionRole"
                )
            ]
        )
        
        # Grant DynamoDB permissions
        self.users_table.grant_read_write_data(lambda_role)
        
        # Grant CloudWatch permissions for monitoring
        lambda_role.add_to_policy(iam.PolicyStatement(
            effect=iam.Effect.ALLOW,
            actions=[
                "cloudwatch:PutMetricData",
                "xray:PutTraceSegments",
                "xray:PutTelemetryRecords"
            ],
            resources=["*"]
        ))
        
        # Lambda function
        self.password_validation_lambda = _lambda.Function(
            self, "PasswordValidationFunction",
            runtime=_lambda.Runtime.PYTHON_3_11,
            architecture=_lambda.Architecture.ARM_64,
            handler="handler.lambda_handler",
            code=_lambda.Code.from_asset("src/features/password_validation/lambda/password_handler"),
            timeout=Duration.seconds(30),
            memory_size=512,
            role=lambda_role,
            environment={
                "USERS_TABLE_NAME": self.users_table.table_name,
                "AWS_REGION": self.region,
                "ENVIRONMENT": "production",
                "LOG_LEVEL": "INFO"
            },
            tracing=_lambda.Tracing.ACTIVE,
            retry_attempts=0,  # Disable retries for idempotency
            reserved_concurrent_executions=100,  # Limit concurrent executions
            dead_letter_queue_enabled=True
        )
        
        # Log group with retention
        logs.LogGroup(
            self, "PasswordValidationLogGroup",
            log_group_name=f"/aws/lambda/{self.password_validation_lambda.function_name}",
            retention=logs.RetentionDays.ONE_MONTH,
            removal_policy=RemovalPolicy.DESTROY
        )
        
        # API Gateway
        self.api = apigateway.LambdaRestApi(
            self, "PasswordValidationApi",
            handler=self.password_validation_lambda,
            proxy=True,
            deploy_options=apigateway.StageOptions(
                stage_name="v1",
                throttling_rate_limit=1000,
                throttling_burst_limit=2000,
                logging_level=apigateway.MethodLoggingLevel.INFO,
                data_trace_enabled=False,  # Disable data tracing for security
                metrics_enabled=True
            ),
            default_cors_preflight_options=apigateway.CorsOptions(
                allow_origins=["*"],
                allow_methods=["GET", "POST", "OPTIONS"],
                allow_headers=["Content-Type", "Authorization", "X-Correlation-ID"]
            ),
            endpoint_configuration=apigateway.EndpointConfiguration(
                types=[apigateway.EndpointType.REGIONAL]
            )
        )
        
        # Request validator for API Gateway
        request_validator = apigateway.RequestValidator(
            self, "PasswordValidationRequestValidator",
            rest_api=self.api,
            validate_request_body=True,
            validate_request_parameters=True
        )
        
        # CloudWatch Alarms
        
        # Error rate alarm
        error_alarm = cloudwatch.Alarm(
            self, "PasswordValidationErrorAlarm",
            metric=self.password_validation_lambda.metric_errors(
                period=Duration.minutes(5)
            ),
            threshold=10,
            evaluation_periods=2,
            alarm_description="Password validation Lambda error rate is high"
        )
        
        # Duration alarm
        duration_alarm = cloudwatch.Alarm(
            self, "PasswordValidationDurationAlarm", 
            metric=self.password_validation_lambda.metric_duration(
                period=Duration.minutes(5)
            ),
            threshold=10000,  # 10 seconds
            evaluation_periods=2,
            alarm_description="Password validation Lambda duration is high"
        )
        
        # Throttle alarm
        throttle_alarm = cloudwatch.Alarm(
            self, "PasswordValidationThrottleAlarm",
            metric=self.password_validation_lambda.metric_throttles(
                period=Duration.minutes(5)
            ), 
            threshold=5,
            evaluation_periods=1,
            alarm_description="Password validation Lambda is being throttled"
        )
        
        # API Gateway 4XX alarm  
        api_4xx_alarm = cloudwatch.Alarm(
            self, "PasswordValidationApi4xxAlarm",
            metric=self.api.metric_client_error(
                period=Duration.minutes(5)
            ),
            threshold=50,
            evaluation_periods=2,
            alarm_description="Password validation API 4xx error rate is high"
        )
        
        # API Gateway 5XX alarm
        api_5xx_alarm = cloudwatch.Alarm(
            self, "PasswordValidationApi5xxAlarm",
            metric=self.api.metric_server_error(
                period=Duration.minutes(5)
            ),
            threshold=10,
            evaluation_periods=1,
            alarm_description="Password validation API 5xx error rate is high"
        )
        
        # SNS topic for alerts (optional)
        alert_topic = sns.Topic(
            self, "PasswordValidationAlerts",
            display_name="Password Validation Service Alerts"
        )
        
        # Add SNS actions to alarms
        sns_action = cw_actions.SnsAction(alert_topic)
        error_alarm.add_alarm_action(sns_action)
        duration_alarm.add_alarm_action(sns_action)
        throttle_alarm.add_alarm_action(sns_action)
        api_4xx_alarm.add_alarm_action(sns_action)
        api_5xx_alarm.add_alarm_action(sns_action)
        
        # Custom metrics dashboard
        dashboard = cloudwatch.Dashboard(
            self, "PasswordValidationDashboard",
            dashboard_name="PasswordValidationService"
        )
        
        # Add widgets to dashboard
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Lambda Invocations",
                left=[self.password_validation_lambda.metric_invocations()],
                width=12,
                height=6
            ),
            cloudwatch.GraphWidget(
                title="Lambda Errors & Duration",
                left=[self.password_validation_lambda.metric_errors()],
                right=[self.password_validation_lambda.metric_duration()],
                width=12,
                height=6
            ),
            cloudwatch.GraphWidget(
                title="API Gateway Metrics",
                left=[self.api.metric_count(), self.api.metric_latency()],
                right=[self.api.metric_client_error(), self.api.metric_server_error()],
                width=12,
                height=6
            ),
            cloudwatch.SingleValueWidget(
                title="DynamoDB Consumed Read Capacity",
                metrics=[self.users_table.metric_consumed_read_capacity_units()],
                width=6,
                height=3
            ),
            cloudwatch.SingleValueWidget(
                title="DynamoDB Consumed Write Capacity", 
                metrics=[self.users_table.metric_consumed_write_capacity_units()],
                width=6,
                height=3
            )
        )