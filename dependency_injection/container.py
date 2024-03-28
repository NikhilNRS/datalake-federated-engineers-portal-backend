import boto3
from dependency_injector import providers, containers

from dependency_injection.resources import DogpileCacheResource
from services.cognito import CognitoService

from dotenv import load_dotenv

from services.tokens import AuthorizationCodeBackend, TokenVerificationService

load_dotenv()


class ServiceContainer(containers.DeclarativeContainer):
    # constants
    COGNITO_SERVICE_NAME = "cognito-idp"

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
    config.aws_region.from_env("AWS_REGION", required=True)

    # dependencies
    boto3_session = providers.Singleton(boto3.session.Session)
    aws_cognito_client = providers.Object(
        boto3_session().client(
            service_name=COGNITO_SERVICE_NAME,
            region_name=config.aws_region()
        )
    )

    dogpile_cache_region = providers.Resource(
        DogpileCacheResource
    )

    cognito_service = providers.Singleton(
        CognitoService,
        aws_cognito_client,
        dogpile_cache_region,
        config.aws_region(),
        config.cognito_user_pool_domain(),
        config.cognito_user_pool_id()
    )

    token_verification_service = providers.Singleton(
        TokenVerificationService
    ).add_args(
        cognito_service
    )

    authorization_code_backend = providers.Singleton(
        AuthorizationCodeBackend
    ).add_args(
        token_verification_service,
        cognito_service,
        dogpile_cache_region
    )
