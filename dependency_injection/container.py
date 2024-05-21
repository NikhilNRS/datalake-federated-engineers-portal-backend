import logging
from typing import Literal

import boto3
from botocore.model import ServiceId
from botocore.signers import RequestSigner
from dependency_injector import providers, containers
from dependency_injector.providers import Provider
from mypy_boto3_cognito_identity import CognitoIdentityClient
from mypy_boto3_cognito_idp import CognitoIdentityProviderClient
from mypy_boto3_secretsmanager import SecretsManagerClient
from mypy_boto3_sts import STSClient

from dependency_injection.resources import DogpileCacheDevResource, \
    DogpileCacheProdResource, get_logger
from services.aws_console import AWSConsoleService
from services.cache import ElasticacheIAMProvider
from services.cognito import CognitoService

from dotenv import load_dotenv

from services.secrets import SecretsService
from services.tokens import AuthorizationCodeBackend, TokenVerificationService

load_dotenv()


class ServiceContainer(containers.DeclarativeContainer):
    # constants
    COGNITO_SERVICE_NAME: Literal["cognito-idp"] = "cognito-idp"
    COGNITO_IDENTITY_SERVICE_NAME: Literal["cognito-identity"] = \
        "cognito-identity"
    STS_SERVICE_NAME: Literal["sts"] = "sts"
    SECRETS_MANAGER_SERVICE_NAME: Literal["secretsmanager"] = "secretsmanager"
    ELASTICACHE_SERVICE_NAME: Literal["elasticache"] = "elasticache"

    # configuration
    config = providers.Configuration()
    config.app_base_url.from_env("APP_BASE_URL", required=True)
    config.cognito_client_id.from_env("COGNITO_CLIENT_ID", required=True)
    config.cognito_user_pool_domain.from_env(
        "COGNITO_USER_POOL_DOMAIN",
        required=True
    )
    config.cognito_user_pool_id.from_env(
        "COGNITO_USER_POOL_ID",
        required=True
    )
    config.cognito_identity_pool_id.from_env(
        "COGNITO_IDENTITY_POOL_ID",
        required=True
    )
    config.aws_region.from_env("AWS_REGION", required=True)
    config.app_env.from_env("APP_ENV", required=True)
    config.cache_secret_name.from_env("CACHE_SECRET_NAME", None)
    config.log_level.from_env("LOG_LEVEL", "WARNING")

    # dependencies
    logger: Provider[logging.Logger] = providers.Callable(
        get_logger
    ).add_args(config.log_level())

    boto3_session = providers.Singleton(boto3.session.Session)
    aws_cognito_client: Provider[CognitoIdentityProviderClient] = \
        providers.Object(
            boto3_session().client(
                service_name=COGNITO_SERVICE_NAME,
                region_name=config.aws_region()
            )
        )
    aws_cognito_identity_client: Provider[CognitoIdentityClient] = \
        providers.Object(
            boto3_session().client(
                service_name=COGNITO_IDENTITY_SERVICE_NAME,
                region_name=config.aws_region()
            )
        )
    aws_sts_client: Provider[STSClient] = providers.Object(
        boto3_session().client(
            service_name=STS_SERVICE_NAME,
            region_name=config.aws_region()
        )
    )

    aws_secrets_manager_client: Provider[SecretsManagerClient] = \
        providers.Object(
            boto3_session().client(
                service_name=SECRETS_MANAGER_SERVICE_NAME,
                region_name=config.aws_region()
            )
        )

    elasticache_service_id = providers.Singleton(
        ServiceId
    ).add_args(ELASTICACHE_SERVICE_NAME)
    boto3_credentials = providers.Callable(
        boto3_session().get_credentials
    )
    boto3_event_aliaser = providers.Object(boto3_session().events)

    aws_request_signer: Provider[RequestSigner] = providers.Singleton(
        RequestSigner
    ).add_args(
        elasticache_service_id,
        config.aws_region(),
        ELASTICACHE_SERVICE_NAME,
        "v4",
        boto3_credentials,
        boto3_event_aliaser
    )

    secrets_service: Provider[SecretsService] = \
        providers.Singleton(SecretsService).add_args(
            aws_secrets_manager_client,
            logger
        )

    if config.app_env() == "development":
        cache_credential_provider: Provider[ElasticacheIAMProvider] | None = \
            None
        config.cache_endpoint.from_value(None)
        config.cache_connection_url.from_env("CACHE_CONNECTION_URL")
    else:
        config.cache_user.from_value(
            secrets_service().get_json_secret(config.cache_secret_name())[
                "user"
            ]
        )
        config.cache_cluster_name.from_value(
            secrets_service().get_json_secret(config.cache_secret_name())[
                "cluster_name"
            ]
        )
        config.cache_endpoint.from_value(
            secrets_service().get_json_secret(config.cache_secret_name())[
                "endpoint"
            ]
        )

        cache_credential_provider = \
            providers.Singleton(
                ElasticacheIAMProvider
            ).add_args(
                config.cache_user(),
                config.cache_cluster_name(),
                aws_request_signer,
                logger
            )

    dogpile_cache_region = providers.Selector(
        config.app_env,
        development=providers.Resource(DogpileCacheDevResource).add_args(
            config.cache_connection_url()
        ),
        production=providers.Resource(DogpileCacheProdResource).add_args(
            config.cache_endpoint(),
            cache_credential_provider
        )
    )

    cognito_service = providers.Singleton(
        CognitoService,
        aws_cognito_client,
        aws_cognito_identity_client,
        dogpile_cache_region,
        logger,
        config.aws_region(),
        config.cognito_user_pool_domain(),
        config.cognito_user_pool_id(),
        config.cognito_identity_pool_id()
    )

    token_verification_service = providers.Singleton(
        TokenVerificationService
    ).add_args(
        cognito_service
    )

    aws_console_service = providers.Singleton(
        AWSConsoleService
    ).add_args(
        aws_sts_client,
        config.app_base_url()
    )

    authorization_code_backend = providers.Singleton(
        AuthorizationCodeBackend
    ).add_args(
        token_verification_service,
        cognito_service,
        dogpile_cache_region,
        aws_console_service
    )
