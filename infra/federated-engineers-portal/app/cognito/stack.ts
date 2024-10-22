import { Construct } from 'constructs';
import * as path from 'path';

import {
    Aws,
    aws_cognito as cognito,
    aws_ec2 as ec2,
    aws_ecr as ecr,
    aws_elasticache as elasticache,
    aws_iam as iam,
    aws_lambda as lambda,
    aws_logs as logs,
    aws_secretsmanager as secretsmanager,
    aws_ssm as ssm,
    aws_s3 as s3,
    Duration,
    RemovalPolicy,
    SecretValue,
    Stack,
    StackProps,
    aws_apprunner as apprunner,
    aws_ecr_assets as ecr_assets,
    aws_wafv2 as waf,
} from 'aws-cdk-lib';
import 'dotenv/config';
import * as ecr_deploy from 'cdk-ecr-deployment';

import { AwsServicePrincipal, Stage, getContextVariable } from '@datalake/dl-utils';
import { FDEAccPrdPolicy, FDEDevTstPolicy } from '../permissions/policy-creation';

export interface CognitoStackProps extends StackProps {
    // name is used as part of most resource IDs and AWS resource names
    readonly name: string;
    readonly stage: Stage;
    readonly access_token_duration: number;
    readonly refresh_token_duration: number;
    readonly id_token_duration: number;
    readonly federated_idp: string;
    readonly federated_idp_saml_metadata_url: string;
    readonly appRunnerURL: string | null;
    readonly image_tag: string;
}

const DEFAULT_REDIS_PORT = 6379;

export interface CognitoGroup {
    readonly groupName: string;
    readonly groupDescription: string;
}

interface CacheDeployment {
    cacheReplicationGroup: elasticache.CfnReplicationGroup,
    cacheUser: elasticache.CfnUser,
    cacheSecret: secretsmanager.Secret,
    cacheSecurityGroup: ec2.SecurityGroup
}

export class CognitoStack extends Stack {
    readonly props: CognitoStackProps;

    constructor(scope: Construct, id: string, props: CognitoStackProps) {
        super(scope, id, props);
        this.props = props;

        const preTokenGenerationLambda = this.deployPreTokenGenerationLambda();

        // The User Pool is used to authenticate that the user is part of PostNL via the federated idp.
        const cognitoPool = this.deployUserPool(preTokenGenerationLambda);

        const user_pool_domain = `${props.name}-${props.stage}`.toLowerCase();

        // Creating a domain ensures the User Pool can be accessed via a URL with a predetermined name.
        cognitoPool.addDomain(`UserPool-Domain`, {
            cognitoDomain: {
                domainPrefix: user_pool_domain,
            },
        });

        // Use the federated idp as the authentication.
        // It is the central point of authentication within the company.
        // It returns the email of the user.
        const OneWelcomeIdProvider = this.createOneWelcomeProvider(cognitoPool);

        // In order to interact with a User Pool there needs to be a User Pool Client/App.
        // It forces the users to authenticate via the federated idp.
        const identityPoolClient = this.deployIdentityPoolAppClient(cognitoPool, OneWelcomeIdProvider, user_pool_domain);

        // 1. Assume a role via get_id -> get_open_id_token -> assume_role_with_web_identity.
        // 2. Login to the AWS console via 1) -> https://signin.aws.amazon.com/federation.
        const identityPool = this.deployIdentityPool(identityPoolClient, cognitoPool);

        // The Federated-IDP tag can be used to control who can assume a role via the RequestTag in the principal policy.
        this.addPrincipalTagMappingToIdentityPool(identityPool, cognitoPool);

        // Fetching the Federated Team Groups
        const groups: string[] = getContextVariable(props.stage, "groups");

        const requiredCognitoGroups: CognitoGroup[] = groups.map(name => ({
            groupName: name,
            groupDescription: `Group for ${name}`,
        }));

        const athenaOuputBucketArn = getContextVariable(props.stage, "athenaOutputBucketArn");
        const athenaOutputBucket = s3.Bucket.fromBucketArn(this, "athena-output-bucket", athenaOuputBucketArn);

        const federatedPrincipal = new iam.FederatedPrincipal("cognito-identity.amazonaws.com").withSessionTags();

        const fdeRoles: iam.CfnRole[] = requiredCognitoGroups.map(group => {
            // Create the Cognito group and role
            const fdeRole: iam.CfnRole = this.createCognitoGroupAndRole(group, cognitoPool, identityPool, federatedPrincipal);

            // Determine the policy creation based on the stage
            // Adding switch statement  for better readability and refactoring if the stage logic changes in future
            let fdePolicyCreation;
            switch (props.stage) {
            case Stage.DEVELOPMENT:
            case Stage.TESTING:
                fdePolicyCreation = new FDEDevTstPolicy(this, `cognito-${group.groupName}-${props.stage}-policy`, {
                    stage: props.stage,
                    tagValue: group.groupName,
                    roleName: fdeRole.roleName!,
                    athenaOutputBucket: athenaOutputBucket,
                });
                break;
            case Stage.PRODUCTION:
            case Stage.ACCEPTANCE:
                fdePolicyCreation = new FDEAccPrdPolicy(this, `cognito-${group.groupName}-${props.stage}-policy`, {
                    stage: props.stage,
                    tagValue: group.groupName,
                    roleName: fdeRole.roleName!,
                    athenaOutputBucket: athenaOutputBucket,
                });
                break;
            }

            // Ensure the policy creation starts after role is created
            fdePolicyCreation.node.addDependency(fdeRole);

            return fdeRole;
        });

        // Extract role names from fdeRoles to attach to fdeCommonPolicies
        const fdeRoleNames: string[] = fdeRoles.filter(role => role.roleName !== undefined).map(role => role.roleName!);

        const fdeCommonPolicies =  new iam.CfnManagedPolicy(this, 'fdeLambdaReadPolicy', {
            managedPolicyName: `${props.stage}-fde-common-policy`,
            policyDocument: {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Action": [
                            "scheduler:GetSchedule",
                            "scheduler:GetScheduleGroup",
                            "scheduler:ListScheduleGroups",
                            "scheduler:ListSchedules",
                            "scheduler:ListTagsForResource",
                        ],
                        "Resource": "*",
                        "Effect": "Allow",
                        "Sid": "EventBridgeSchedulerListAccess",
                    },
                    {
                        "Action": [
                            "events:DescribeApiDestination",
                            "events:DescribeArchive",
                            "events:DescribeConnection",
                            "events:DescribeEndpoint",
                            "events:DescribeEventBus",
                            "events:DescribeEventSource",
                            "events:DescribePartnerEventSource",
                            "events:DescribeReplay",
                            "events:DescribeRule",
                            "events:ListApiDestinations",
                            "events:ListArchives",
                            "events:ListConnections",
                            "events:ListEndpoints",
                            "events:ListEventBuses",
                            "events:ListEventSources",
                            "events:ListPartnerEventSourceAccounts",
                            "events:ListPartnerEventSources",
                            "events:ListReplays",
                            "events:ListRuleNamesByTarget",
                            "events:ListRules",
                            "events:ListTagsForResource",
                            "events:ListTargetsByRule",
                            "events:TestEventPattern",
                        ],
                        "Resource": "*",
                        "Effect": "Allow",
                        "Sid": "EventBusRead",
                    },
                    {
                        "Action": [
                            "cloudwatch:BatchGetServiceLevelIndicatorReport",
                            "cloudwatch:DescribeAlarmHistory",
                            "cloudwatch:DescribeAlarms",
                            "cloudwatch:DescribeAlarmsForMetric",
                            "cloudwatch:DescribeAnomalyDetectors",
                            "cloudwatch:DescribeInsightRules",
                            "cloudwatch:GenerateQuery",
                            "cloudwatch:GetDashboard",
                            "cloudwatch:GetInsightRuleReport",
                            "cloudwatch:GetMetricData",
                            "cloudwatch:GetMetricStatistics",
                            "cloudwatch:GetMetricStream",
                            "cloudwatch:GetMetricWidgetImage",
                            "cloudwatch:GetService",
                            "cloudwatch:GetServiceData",
                            "cloudwatch:GetServiceLevelObjective",
                            "cloudwatch:GetTopologyDiscoveryStatus",
                            "cloudwatch:GetTopologyMap",
                            "cloudwatch:ListDashboards",
                            "cloudwatch:ListManagedInsightRules",
                            "cloudwatch:ListMetricStreams",
                            "cloudwatch:ListMetrics",
                            "cloudwatch:ListServiceLevelObjectives",
                            "cloudwatch:ListServices",
                            "cloudwatch:ListTagsForResource",
                        ],
                        "Resource": "*",
                        "Effect": "Allow",
                        "Sid": "CloudwatchRead",
                    },
                    {
                        "Action": [
                            "logs:DescribeLogStreams",
                            "logs:DescribeMetricFilters",
                            "logs:DescribeSubscriptionFilters",
                            "logs:FilterLogEvents",
                            "logs:GetDataProtectionPolicy",
                            "logs:GetDelivery",
                            "logs:GetDeliveryDestination",
                            "logs:GetDeliveryDestinationPolicy",
                            "logs:GetDeliverySource",
                            "logs:GetLogAnomalyDetector",
                            "logs:GetLogEvents",
                            "logs:GetLogGroupFields",
                            "logs:GetLogRecord",
                            "logs:GetQueryResults",
                            "logs:ListAnomalies",
                            "logs:ListLogAnomalyDetectors",
                            "logs:ListTagsForResource",
                            "logs:ListTagsLogGroup",
                            "logs:StartLiveTail",
                            "logs:StartQuery",
                            "logs:Unmask",
                        ],
                        "Resource": `arn:aws:logs:eu-west-1:${Aws.ACCOUNT_ID}:log-group:/aws-glue/jobs/error`,
                        "Effect": "Allow",
                        "Sid": "CloudwatchGlueErrorLogsReadAccess",
                    },
                    {
                        "Action": "s3:ListAllMyBuckets",
                        "Resource": "*",
                        "Effect": "Allow",
                        "Sid": "S3ListBuckets",
                    },
                    {
                        "Action": "s3:ListBucket",
                        "Resource": [
                            `arn:aws:s3:::postnl-dl-${props.stage}-refine-non-pii`,
                            `arn:aws:s3:::postnl-dl-${props.stage}-refine-non-pii/*`,
                            `arn:aws:s3:::postnl-dl-${props.stage}-refine-pii`,
                            `arn:aws:s3:::postnl-dl-${props.stage}-refine-pii/*`,
                        ],
                        "Effect": "Allow",
                        "Sid": "S3ListRefineBuckets",
                    },
                ],
            },
            roles: fdeRoleNames,
        });

        // Add dependencies to ensure fdeCommonPolicies depends on the roles being created first
        fdeRoles.forEach(fdeRole => {
            fdeCommonPolicies.node.addDependency(fdeRole);
        });


        // Components for portal backend deployment
        const ecrRepository = new ecr.Repository(this, "FederatedEngineersPortalBackendImages", {
            repositoryName: `federated-engineers-portal-backend-${props.stage}`,
            imageScanOnPush: true,
        });

        // Build and push dummy Docker image to the ECR repository for initial deployment
        const dockerImageAsset = new ecr_assets.DockerImageAsset(this, 'MyDockerImage', {
            directory: path.join(__dirname, './docker')});
        dockerImageAsset.node.addDependency(ecrRepository);

        const deployAsset = new ecr_deploy.ECRDeployment(this, 'DeployDockerImage', {
            src: new ecr_deploy.DockerImageName(dockerImageAsset.imageUri),
            dest: new ecr_deploy.DockerImageName(ecrRepository.repositoryUriForTag("dummy")),
        });
        deployAsset.node.addDependency(dockerImageAsset);

        const vpc = this.getVpc();

        const {
            cacheReplicationGroup,
            cacheUser,
            cacheSecret,
            cacheSecurityGroup,
        } = this.deployLoginPortalCache(vpc);

        //TODO:
        // Chicken egg issue with the app base url in identityPool : Will be fixed after implementation of Static url's via route53

        const FDEBackendExecutionRole: iam.Role = this.deployFederatedEngineersPortalBackendExecutionRole(
            cognitoPool,
            cacheReplicationGroup,
            cacheUser,
            cacheSecret,
        );
        const FDEBackendAccessRole: iam.Role = this.deployFederatedEngineersPortalBackendECRRole(ecrRepository);

        const LoginPortalAutoscalingGroup = new apprunner.CfnAutoScalingConfiguration(this, 'LoginPortalAutoscalingGroup', {
            autoScalingConfigurationName: `fde-autoscaling-group-${props.stage}`,
            maxConcurrency: 100,
            maxSize: 2,
        });

        const LoginPortalVpcConnector = new apprunner.CfnVpcConnector(this, 'LoginPortalVpcConnector', {
            subnets: [this.getPrivateSubnetId(1)],
            securityGroups: [this.getWebSecurityGroup('web-prod'), cacheSecurityGroup.securityGroupId],
            vpcConnectorName: `fde-vpc-connector-${props.stage}`,
        });

        const FDELoginPortalService = new apprunner.CfnService(this, 'FDELoginPortalService', {
            sourceConfiguration: {
                authenticationConfiguration: {
                    accessRoleArn: FDEBackendAccessRole.roleArn,
                },
                autoDeploymentsEnabled: false,
                imageRepository: {
                    imageIdentifier: ecrRepository.repositoryUriForTag(props.image_tag),
                    imageRepositoryType: 'ECR',
                    imageConfiguration: {
                        port: '80',
                        runtimeEnvironmentVariables: [
                            {
                                name: 'COGNITO_USER_POOL_ID',
                                value: cognitoPool.userPoolId,
                            },
                            {
                                name: 'COGNITO_IDENTITY_POOL_ID',
                                value: identityPool.attrId,
                            },
                            {
                                name: 'APP_ENV',
                                value: 'aws', // Accepted values "aws"|"local" - In case for local development / debugging -> local
                            },
                            {
                                name: 'CACHE_SECRET_NAME',
                                value: cacheSecret.secretName,
                            },
                            {
                                name: 'COGNITO_CLIENT_ID',
                                value: identityPoolClient.userPoolClientId,
                            },
                            {
                                name: 'LOG_LEVEL',
                                value: 'INFO',
                            },
                            {
                                name: 'COGNITO_USER_POOL_DOMAIN',
                                value: user_pool_domain,
                            },
                        ],
                    },
                },
            },
            healthCheckConfiguration: {
                healthyThreshold: 1,
                interval: 10,
                protocol: 'TCP',
                timeout: 5,
                unhealthyThreshold: 5,
            },
            instanceConfiguration: {
                cpu: '0.5 vCPU',
                instanceRoleArn: FDEBackendExecutionRole.roleArn,
                memory: '1 GB',
            },
            autoScalingConfigurationArn: LoginPortalAutoscalingGroup.attrAutoScalingConfigurationArn,
            networkConfiguration: {
                egressConfiguration: {
                    egressType: 'VPC',
                    vpcConnectorArn: LoginPortalVpcConnector.attrVpcConnectorArn,
                },
                ingressConfiguration: {
                    isPubliclyAccessible: true,
                },
            },
            serviceName: `fde-portal-login-${props.stage}`,
        });
        FDELoginPortalService.node.addDependency(LoginPortalAutoscalingGroup, LoginPortalVpcConnector, deployAsset);

        const webACL = this.deployWebApplicationFirewall(FDELoginPortalService);

        webACL.node.addDependency(FDELoginPortalService);
    }

    private deployFederatedEngineersPortalBackendECRRole(ecrRepository: ecr.Repository): iam.Role {
        return new iam.Role(this, "PortalBackendECRAccessRole", {
            roleName: "PortalBackendECRAccessRole",
            assumedBy: new iam.ServicePrincipal(AwsServicePrincipal.APPRUNNER_BUILD),
            managedPolicies: [],
            inlinePolicies: {
                "ECRAccessPolicy": new iam.PolicyDocument({
                    statements: [
                        new iam.PolicyStatement({
                            sid: "AllowGetAuthorizationToken",
                            effect: iam.Effect.ALLOW,
                            actions: [
                                "ecr:GetAuthorizationToken",
                            ],
                            resources: [
                                "*",
                            ],
                        }),
                        new iam.PolicyStatement({
                            sid: "AllowRepositorySpecificActions",
                            effect: iam.Effect.ALLOW,
                            actions: [
                                "ecr:GetDownloadUrlForLayer",
                                "ecr:BatchGetImage",
                                "ecr:DescribeImages",
                                "ecr:BatchCheckLayerAvailability",
                            ],
                            resources: [
                                ecrRepository.repositoryArn,
                            ],
                        }),
                    ],
                }),
            },
        });
    }

    private deployFederatedEngineersPortalBackendExecutionRole(
        cognitoPool: cognito.UserPool,
        cacheReplicationGroup: elasticache.CfnReplicationGroup,
        cacheUser: elasticache.CfnUser,
        cacheSecret: secretsmanager.Secret,
    ): iam.Role {
        return new iam.Role(this, "PortalBackendExecutionRole", {
            roleName: "PortalBackendExecutionRole",
            assumedBy: new iam.ServicePrincipal(AwsServicePrincipal.APPRUNNER_TASKS),
            managedPolicies: [],
            inlinePolicies: {
                "PortalBackendExecutionRolePolicy": new iam.PolicyDocument({
                    statements: [
                        new iam.PolicyStatement({
                            sid: "AllowCognitoUserPoolCalls",
                            effect: iam.Effect.ALLOW,
                            actions: [
                                "cognito-idp:DescribeUserPoolClient",
                                "cognito-idp:GetGroup",
                            ],
                            resources: [
                                cognitoPool.userPoolArn,
                            ],
                        }),
                        new iam.PolicyStatement({
                            sid: "AllowCognitoIdentityPoolCalls",
                            effect: iam.Effect.ALLOW,
                            actions: [
                                "cognito-idp:GetId",
                                "cognito-idp:GetOpenIdToken",
                            ],
                            resources: [
                                "*",
                            ],
                        }),
                        new iam.PolicyStatement({
                            sid: "AllowFetchingTempCredentialsForUser",
                            effect: iam.Effect.ALLOW,
                            actions: [
                                "sts:AssumeRoleWithWebIdentity",
                            ],
                            resources: [
                                "*",
                            ],
                        }),
                        new iam.PolicyStatement({
                            sid: "AllowFetchingCacheCredentials",
                            effect: iam.Effect.ALLOW,
                            actions: [
                                "secretsmanager:GetSecretValue",
                            ],
                            resources: [
                                cacheSecret.secretArn,
                            ],
                        }),
                        new iam.PolicyStatement({
                            sid: "AllowConnectionToCache",
                            effect: iam.Effect.ALLOW,
                            actions: [
                                "elasticache:Connect",
                            ],
                            resources: [
                                "*",
                            ],
                        }),
                    ],
                }),
            },
        });
    }

    private addPrincipalTagMappingToIdentityPool(
        identityPool: cognito.CfnIdentityPool,
        cognitoPool: cognito.UserPool,
    ) {
        new cognito.CfnIdentityPoolPrincipalTag(this, `${this.props.name}-${this.props.federated_idp}-PrincipalTags`, {
            identityPoolId: identityPool.ref,
            identityProviderName: `cognito-idp.eu-west-1.amazonaws.com/${cognitoPool.userPoolId}`,
            principalTags: {
                "user_email": "email",
                "user_groups": "user_groups",
            },
        });
    }

    private deployIdentityPool(
        identityPoolClient: cognito.UserPoolClient,
        cognitoPool: cognito.UserPool,
    ) {
        return new cognito.CfnIdentityPool(
            this,
            `${this.props.name}-${this.props.federated_idp}-IdentityPool`,
            {
                identityPoolName: `${this.props.name}-${this.props.federated_idp}`,
                allowClassicFlow: true,
                allowUnauthenticatedIdentities: false,
                cognitoIdentityProviders: [
                    {
                        clientId: identityPoolClient.userPoolClientId,
                        providerName: `cognito-idp.eu-west-1.amazonaws.com/${cognitoPool.userPoolId}`,
                        serverSideTokenCheck: true,
                    },
                ],
            });
    }

    private deployIdentityPoolAppClient(
        cognitoPool: cognito.UserPool,
        OneWelcomeIdProvider: cognito.CfnUserPoolIdentityProvider,
        user_pool_domain: string,
    ) {
        const callbackUrls = [`https://${user_pool_domain}.auth.eu-west-1.amazoncognito.com/oauth2/idpresponse`, "http://localhost:8000/"];
        const logoutUrls = ["http://localhost:8000/welcome"];

        if(this.props.appRunnerURL !== null) {
            callbackUrls.push(this.props.appRunnerURL);
            logoutUrls.push(`${this.props.appRunnerURL}welcome`);
        }

        const identityPoolClient = cognitoPool.addClient(this.props.federated_idp, {
            userPoolClientName: `${this.props.federated_idp}`,
            accessTokenValidity: Duration.seconds(this.props.access_token_duration),
            refreshTokenValidity: Duration.seconds(this.props.refresh_token_duration),
            idTokenValidity: Duration.seconds(this.props.id_token_duration),
            enableTokenRevocation: true,
            oAuth: {
                callbackUrls: callbackUrls,
                flows: {authorizationCodeGrant: true},
                scopes: [cognito.OAuthScope.OPENID],
                logoutUrls: logoutUrls,
            },
            supportedIdentityProviders: [cognito.UserPoolClientIdentityProvider.custom(this.props.federated_idp)],
        });

        identityPoolClient.node.addDependency(OneWelcomeIdProvider);
        return identityPoolClient;
    }

    private createOneWelcomeProvider(cognitoPool: cognito.UserPool) {
        return new cognito.CfnUserPoolIdentityProvider(this, "UserPool-IdentityProvider", {
            providerName: this.props.federated_idp,
            providerType: "SAML",
            providerDetails: {
                MetadataURL: this.props.federated_idp_saml_metadata_url,
                IDPSignout: false,
            },
            userPoolId: cognitoPool.userPoolId,
            attributeMapping: {
                email: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                given_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/firstname",
                family_name: "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname",
            },
        });
    }

    private deployUserPool(preTokenGenerationLambda: lambda.Function) {
        return new cognito.UserPool(this, `UserPool`, {
            userPoolName: `${this.props.name}-${this.props.federated_idp}`,
            signInCaseSensitive: false,
            signInAliases: {email: true},
            selfSignUpEnabled: false,
            standardAttributes: {
                email: {required: true, mutable: true},
            },
            lambdaTriggers: {
                preTokenGeneration: preTokenGenerationLambda,
            },
            accountRecovery: cognito.AccountRecovery.NONE,
            deletionProtection: true,
            removalPolicy: RemovalPolicy.RETAIN_ON_UPDATE_OR_DELETE,
        });
    }

    private deployPreTokenGenerationLambda() {
        return new lambda.Function(this, 'preTokenGenerationLambda', {
            functionName: "preTokenGenerationLambda",
            runtime: lambda.Runtime.PYTHON_3_11,
            code: lambda.Code.fromAsset(
                "./app/pre_token_generation_lambda",
                {
                    bundling: {
                        image: lambda.Runtime.PYTHON_3_11.bundlingImage,
                        command: [
                            'bash', '-c',
                            'pip install -r requirements.txt -t /asset-output && cp -au . /asset-output',
                        ],
                    },
                },
            ),
            handler: "src.main.lambda_handler",
        });
    }

    private createCognitoGroupAndRole(
        cognitoGroup: CognitoGroup,
        userPool: cognito.UserPool,
        identityPool: cognito.CfnIdentityPool,
        federatedPrincipal: iam.PrincipalBase,
    ): iam.CfnRole {
        const trustPolicy = new iam.PolicyDocument({
            statements: [
                new iam.PolicyStatement({
                    sid: `${cognitoGroup.groupName}TrustPolicy`,
                    actions: [
                        "sts:AssumeRoleWithWebIdentity",
                        "sts:TagSession",
                    ],
                    principals: [federatedPrincipal],
                    conditions: {
                        "StringEquals": {"cognito-identity.amazonaws.com:aud": identityPool.ref},
                        "StringLike": {"aws:RequestTag/user_groups": `*:${cognitoGroup.groupName}:*`},
                        "ForAnyValue:StringLike": {"cognito-identity.amazonaws.com:amr": "authenticated"},
                    },
                }),
            ],
        });

        const roleName = `fde-${cognitoGroup.groupName}-role`;
        const role = new iam.CfnRole(this, roleName, {
            roleName: roleName,
            assumeRolePolicyDocument: trustPolicy,
        });

        new cognito.CfnUserPoolGroup(this, `${cognitoGroup.groupName}Group`, {
            userPoolId: userPool.userPoolId,
            groupName: cognitoGroup.groupName,
            description: cognitoGroup.groupDescription,
            roleArn: role.attrArn,
        });

        return role;
    }

    private deployLoginPortalCache(vpc: ec2.IVpc): CacheDeployment {
        const subnetGroup = new elasticache.CfnSubnetGroup(this, "CacheSubnetGroup", {
            cacheSubnetGroupName: "FDEPortalCacheSubnetGroup",
            description: "Subnet Group for the Federated Engineers Login portal cache",
            subnetIds: [this.getPrivateSubnetId(1)],
        });

        const portalUser = new elasticache.CfnUser(this, "FDEPortalUser", {
            engine: "redis",
            userId: "fde-portal-user",
            userName: "fde-portal-user",
            authenticationMode: {
                "Type": "iam",
            },
            accessString: "on ~* +@all",
        });

        /* Every user group is obliged to have a user with username default.
         * Without it, the user group cannot be created. Hence, we follow the steps below to implement this securely:
         * https://medium.com/aeturnuminc/securing-redis-with-access-control-lists-acls-54623606f411
         */
        const defaultUserPassword = new secretsmanager.Secret(this, "defaultUserPassword", {
            secretName: "restricted-default-cache-password",
            description: "Password for the secured cache user",
            generateSecretString: {
                passwordLength: 120,
                excludeCharacters: ",\"'.?:#%`~)(*+/\\;=@[]`|}{",
            },
        });

        const defaultRestrictedUser = new elasticache.CfnUser(this, "defaultRestrictedUser", {
            engine: "redis",
            userId: "restricted-default-user",
            userName: "default",
            authenticationMode: {
                "Type": "password",
                // unfortunately we have to expose this temporary value, as authentication mode offers no support
                // for reading secretValue securely.
                "Passwords": [defaultUserPassword.secretValue.unsafeUnwrap()],
            },
            // The access rule below ensures: inactive, can't execute any command nor access any key
            // or channel
            accessString: "off -@all",
        });

        defaultRestrictedUser.node.addDependency(defaultUserPassword);


        const portalUserGroup = new elasticache.CfnUserGroup(this, "FDEPortalUserGroup", {
            engine: "redis",
            userGroupId: "fde-portal-user-group",
            userIds: [defaultRestrictedUser.userId, portalUser.userId],
        });

        portalUserGroup.node.addDependency(portalUser, defaultRestrictedUser);

        const cacheSecurityGroup = new ec2.SecurityGroup(this, `CacheSecurityGroup`, {
            securityGroupName: "CacheSecurityGroup",
            description: `Inbound Federated Engineers Login Portal Cache security group`,
            vpc: vpc,
            allowAllOutbound: false,
        });

        const cacheLogGroup = new logs.LogGroup(this, "CacheLogGroup", {
            logGroupClass: logs.LogGroupClass.STANDARD,
            logGroupName: "/aws/elasticache/fde-portal-cache",
            retention: logs.RetentionDays.THREE_MONTHS,
        });

        cacheLogGroup.applyRemovalPolicy(RemovalPolicy.DESTROY);

        const replicationGroup = new elasticache.CfnReplicationGroup(
            this,
            "CacheReplicationGroup",
            {
                // general settings
                replicationGroupId: "FDE-portal-cache",
                replicationGroupDescription: "Federated Engineers Login Portal Cache",

                // instance settings
                cacheNodeType: "cache.t4g.micro",
                clusterMode: "disabled",
                automaticFailoverEnabled: false,
                numNodeGroups: 1,
                nodeGroupConfiguration: [{
                    nodeGroupId: "0001",
                    primaryAvailabilityZone: "eu-west-1a",

                }],

                // maintenance settings
                preferredMaintenanceWindow: "mon:00:00-mon:04:00",
                snapshotWindow: "22:45-23:45",
                // for now, backups are not needed
                snapshotRetentionLimit: 0,
                autoMinorVersionUpgrade: true,

                // software settings
                engine: "redis",
                engineVersion: "7.1",

                // network settings
                port: 6379,
                cacheSubnetGroupName: subnetGroup.cacheSubnetGroupName,
                securityGroupIds: [cacheSecurityGroup.securityGroupId],

                // security settings
                atRestEncryptionEnabled: true,
                transitEncryptionEnabled: true,
                transitEncryptionMode: "required",
                userGroupIds: [portalUserGroup.userGroupId],

                // logging config
                logDeliveryConfigurations: [{
                    destinationDetails: {
                        cloudWatchLogsDetails: {
                            logGroup: cacheLogGroup.logGroupName,
                        },
                    },
                    destinationType: "cloudwatch-logs",
                    logFormat: "json",
                    logType: "engine-log",
                }],
            },
        );

        cacheSecurityGroup.addIngressRule(
            ec2.Peer.ipv4(vpc.vpcCidrBlock),
            ec2.Port.tcp(replicationGroup.port ?? DEFAULT_REDIS_PORT),
        );

        replicationGroup.node.addDependency(subnetGroup, portalUserGroup, cacheSecurityGroup, cacheLogGroup);

        const clusterGroupId = replicationGroup.replicationGroupId ? replicationGroup.replicationGroupId : "";
        const primaryClusterEndpoint = replicationGroup.attrPrimaryEndPointAddress;

        const portalUserSecret = new secretsmanager.Secret(this, "PortalUserSecret", {
            secretName: "fde-portal-backend-cache-secret",
            description: "Necessary information to generate cache credentials for the FDE Login Portal backend",
            secretObjectValue: {
                "cluster_name": SecretValue.unsafePlainText(clusterGroupId.toLowerCase()),
                "endpoint": SecretValue.unsafePlainText(primaryClusterEndpoint),
                "user": SecretValue.unsafePlainText(portalUser.userName),
            },
        });

        return {
            cacheUser: portalUser,
            cacheReplicationGroup: replicationGroup,
            cacheSecret: portalUserSecret,
            cacheSecurityGroup: cacheSecurityGroup,
        };
    }

    private deployWebApplicationFirewall(appRunnerService: apprunner.CfnService) {
        const webACL = new waf.CfnWebACL(this, "FDEPortalWebApplicationFirewall", {
            defaultAction: {
                allow: {},
            },
            scope: "REGIONAL",
            name: `fde-portal-WAF-${this.props.stage}`,
            description: "Web Application Firewall for the FDE Login portal",
            visibilityConfig: {
                sampledRequestsEnabled: true,
                cloudWatchMetricsEnabled: true,
                metricName: "fde-portal-web-acl",
            },
            rules: [
                {
                    name: "fdePortalRateLimitRule",
                    priority: 0,
                    action: {
                        block: {},
                    },
                    statement: {
                        rateBasedStatement: {
                            // 5 requests / second = 300 requests / minute
                            limit: 300,
                            aggregateKeyType: "CONSTANT",
                            // specify the length of the time-window we should look at to
                            // determine whether we go above the limit
                            evaluationWindowSec: 60,
                            scopeDownStatement: {
                                byteMatchStatement: {
                                    fieldToMatch: {
                                        uriPath: {},
                                    },
                                    positionalConstraint: "EXACTLY",
                                    searchString: "/",
                                    textTransformations: [
                                        {
                                            type: "NONE",
                                            priority: 0,
                                        },
                                    ],
                                },
                            },
                        },
                    },
                    visibilityConfig: {
                        sampledRequestsEnabled: true,
                        cloudWatchMetricsEnabled: true,
                        metricName: "fde-portal-rate-limit-rule",
                    },
                },
            ],
        });

        new waf.CfnWebACLAssociation(
            this,
            `FDEPortalWebACLAssociation-${this.props.stage}`, {
                resourceArn: appRunnerService.attrServiceArn,
                webAclArn: webACL.attrArn,
            },
        );

        return webACL;
    }

    private getVpc(): ec2.IVpc {
        const vpcId = ssm.StringParameter.valueFromLookup(this, '/lpe/vpc/vpc-id');
        return ec2.Vpc.fromLookup(this, `${this.props.stage}-VpcLookup`, {
            vpcId: vpcId,
        });
    }

    private getPrivateSubnetId(subnetNumber: number): string {
        return ssm.StringParameter.valueFromLookup(this, `/lpe/vpc/private-subnet-${subnetNumber}-id`);
    }

    private getWebSecurityGroup(securityGroupName: string): string {
        return ssm.StringParameter.valueFromLookup(this, `/lpe/security-group/${securityGroupName}`);
    }

    private generateReplicationGroupArn(replicationGroup: elasticache.CfnReplicationGroup): string {
        /*
        * Generates the ReplicationGroup ARN as it is not available through the CloudFormation Resource
        * */
        return `arn:aws:elasticache:${this.region}:${this.account}:replicationgroup:${replicationGroup.replicationGroupId}`;
    }
}
