import urllib.parse
import logging
from dotenv import load_dotenv

from fastapi import HTTPException
from fastapi.security import SecurityScopes
from starlette import status
from starlette.requests import Request
from starsessions import load_session

from dependency_injection.container import ServiceContainer
from models.enums import AuthorizeRequestResponseTypes
from utils.urls import generate_app_base_url

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load environment variables from .env file
load_dotenv()


async def check_user_login(
    request: Request,
    security_scopes: SecurityScopes,
):
    service_container: ServiceContainer = request.app.state.service_container
    # Get the environment variable
    app_env = service_container.config.app_env()

    # Conditionally set app_base_url based on the environment
    app_base_url = generate_app_base_url(request, app_env)

    client_id = service_container.config.cognito_client_id()
    redirect_url = f"{app_base_url}/"
    cognito_service = service_container.cognito_service()

    logger.debug(f"App base URL: {app_base_url}")
    logger.debug(f"Client ID: {client_id}")
    logger.debug(f"Redirect URL: {redirect_url}")

    # load the session so that we can store the pkce secret
    await load_session(request)

    if not request.user.is_authenticated:
        pkce_secret_generator = service_container.pkce_secret_generator()
        pkce_secret_session_key = service_container.config\
            .session_pkce_secret_key()
        pkce_secret = pkce_secret_generator.generate_pkce_secret()

        # store pkce secret in session
        request.session[pkce_secret_session_key] = pkce_secret.model_dump(
            exclude={"code_verifier_hash"}
        )

        query_params = {
            "response_type":
                AuthorizeRequestResponseTypes.AUTHORIZATION_CODE.value,
            "client_id": client_id,
            "redirect_uri": redirect_url,
            "code_challenge": pkce_secret.code_challenge,
            "code_challenge_method": "S256"
        }

        query_params_str = urllib.parse.urlencode(query_params)

        cognito_authorize_url = \
            f"{cognito_service.get_authorize_endpoint()}?{query_params_str}"

        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={'Location': cognito_authorize_url}
        )
