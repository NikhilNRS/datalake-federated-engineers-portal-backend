import urllib.parse

from fastapi import HTTPException
from fastapi.security import SecurityScopes
from starlette import status
from starlette.requests import Request

from dependency_injection.container import ServiceContainer
from models.enums import AuthorizeRequestResponseTypes


async def check_user_login(
    request: Request,
    security_scopes: SecurityScopes,
):
    service_container: ServiceContainer = request.app.state.service_container
    client_id = service_container.config.cognito_client_id()
    redirect_url = f"{service_container.config.app_base_url()}/"
    cognito_service = service_container.cognito_service()

    if not request.user.is_authenticated:
        # TODO: Call Cognito service here and store only the
        #  code challenge in a cookie. See:
        #  https://stackoverflow.com/q/74430285/10243474
        #  We can achieve this through an http header as follows:
        #  https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie
        #  Or use the server-side session for this purpose
        query_params = {
            "response_type":
                AuthorizeRequestResponseTypes.AUTHORIZATION_CODE.value,
            "client_id": client_id,
            "redirect_uri": redirect_url
        }
        query_params_str = urllib.parse.urlencode(query_params)

        cognito_authorize_url = \
            f"{cognito_service.get_authorize_endpoint()}?{query_params_str}"

        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={'Location': cognito_authorize_url}
        )
