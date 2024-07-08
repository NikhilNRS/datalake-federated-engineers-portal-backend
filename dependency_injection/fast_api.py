import urllib.parse

from fastapi import HTTPException
from fastapi.security import SecurityScopes
from starlette import status
from starlette.requests import Request
from starsessions import load_session

from dependency_injection.container import ServiceContainer
from models.enums import AuthorizeRequestResponseTypes


async def check_user_login(
    request: Request,
    security_scopes: SecurityScopes,
):
    app_base_url = f"{request.url.scheme}://{request.url.netloc}"
    service_container: ServiceContainer = request.app.state.service_container
    client_id = service_container.config.cognito_client_id()
    redirect_url = f"{app_base_url}/"
    cognito_service = service_container.cognito_service()

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
