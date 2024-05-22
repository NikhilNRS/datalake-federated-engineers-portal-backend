from typing import Optional, Any

import requests
import starsessions
from dogpile.cache import CacheRegion
from dogpile.cache.api import CachedValue, NoValue
from jose import JWTError, jwt
from jose.backends.base import Key
from starlette.authentication import AuthenticationBackend, AuthCredentials, \
    BaseUser, UnauthenticatedUser
from starlette.requests import HTTPConnection

from models.enums import TokenRequestGrantTypes, TokenUseTypes
from models.users import CognitoUser
from services.aws_console import AWSConsoleService
from services.cognito import CognitoService


class TokenVerificationService:
    VALID_TOKEN_TYPES = [TokenUseTypes.ACCESS_TOKEN, TokenUseTypes.ID_TOKEN]

    def __init__(self, cognito_service: CognitoService):
        self._cognito_service = cognito_service

    def is_valid_access_token(
        self,
        access_token: str,
    ) -> bool:
        decoded_token = self.decode_access_token(access_token)
        if decoded_token:
            has_valid_client_id = self._has_valid_client_id(
                decoded_token["client_id"]
            )
            has_valid_token_type = self._has_valid_token_type(
                decoded_token.get("token_use")
            )

            return all(
                (
                    decoded_token,
                    has_valid_client_id,
                    has_valid_token_type
                )
            )
        else:
            return False

    def is_valid_id_token(self, id_token: str, access_token: str):
        decoded_token = self.decode_id_token(id_token, access_token)
        if decoded_token:
            has_valid_token_type = self._has_valid_token_type(
                decoded_token.get("token_use")
            )

            return all(
                (
                    decoded_token,
                    has_valid_token_type
                )
            )
        else:
            return False

    def decode_id_token(
        self,
        id_token: str,
        access_token: str
    ) -> Optional[dict]:
        try:
            token_header = jwt.get_unverified_header(id_token)
            token_payload = jwt.get_unverified_claims(id_token)

            token_key_id = token_header.get("kid")
            cognito_key = self._get_json_web_key(token_key_id)
            token_client_id = self._get_client_id_from_token(token_payload)

            # ensure we handle None cases appropriately
            assert cognito_key is not None
            assert token_client_id is not None

            cognito_client_id = self._cognito_service.get_user_pool_client(
               token_client_id
            )

            decoded_token = jwt.decode(
                token=id_token,
                key=cognito_key.to_dict(),
                audience=cognito_client_id,
                algorithms=cognito_key.to_dict().get("alg"),
                issuer=self._cognito_service.get_issuer_url(),
                access_token=access_token
            )
        except (JWTError, AssertionError):
            return None

        return decoded_token

    def decode_access_token(
        self,
        access_token: str
    ) -> Optional[dict[str, Any]]:

        try:
            token_header = jwt.get_unverified_header(access_token)
            token_key_id = token_header.get("kid")
            cognito_key = self._get_json_web_key(token_key_id)

            # Handle None cases properly
            assert cognito_key is not None

            decoded_token = jwt.decode(
                token=access_token,
                key=cognito_key.to_dict(),
                algorithms=cognito_key.to_dict().get("alg"),
                issuer=self._cognito_service.get_issuer_url()
            )
        except (JWTError, AssertionError):
            return None

        return decoded_token

    @staticmethod
    def _get_client_id_from_token(token_payload: dict) -> Optional[str]:
        token_use_type = TokenVerificationService._get_token_use_type(
            token_payload)

        if token_use_type == TokenUseTypes.ACCESS_TOKEN:
            return token_payload["client_id"]
        elif token_use_type == TokenUseTypes.ID_TOKEN:
            return token_payload["aud"]
        else:
            return None

    @staticmethod
    def _get_token_use_type(token_payload: dict) -> TokenUseTypes:
        return TokenUseTypes(token_payload["token_use"])

    def _get_json_web_key(self, key_id) -> Optional[Key]:
        return self._cognito_service.get_json_web_key(key_id)

    def _has_valid_token_type(self, token_type: Optional[str]):
        return TokenUseTypes(token_type) in self.VALID_TOKEN_TYPES

    def _has_valid_client_id(self, client_id: str) -> bool:
        cognito_client_id = self._cognito_service.get_user_pool_client(
            client_id
        )

        return bool(cognito_client_id)


class AuthorizationCodeBackend(AuthenticationBackend):
    GRANT_TYPE_PARAMETER = "grant_type"
    AUTHORIZATION_CODE_PARAMETER = "code"
    CLIENT_ID_PARAMETER = "client_id"
    REDIRECT_URI_PARAMETER = "redirect_uri"
    CODE_VERIFIER_PARAMETER = "code_verifier"
    ACCESS_TOKEN_KEY = "access_token"
    ID_TOKEN_KEY = "id_token"
    EMAIL_CLAIM_KEY = "email"
    COGNITO_GROUPS_KEY = "cognito:groups"
    FIRST_NAME_CLAIM_KEY = "given_name"
    LAST_NAME_CLAIM_KEY = "family_name"
    USER_SESSION_KEY = "user_session_info"
    GROUP_LOGIN_LINKS_KEY = "group_login_link_mapping"

    def __init__(
        self,
        token_verification_service: TokenVerificationService,
        cognito_service: CognitoService,
        cache_client: CacheRegion,
        aws_console_service: AWSConsoleService
    ):
        self._token_verifier = token_verification_service
        self._cognito_service = cognito_service
        self._cache = cache_client
        self._aws_console_service = aws_console_service

    async def authenticate(
        self,
        conn: HTTPConnection
    ) -> tuple[AuthCredentials, BaseUser] | None:
        authorization_code = conn.query_params.get(
            self.AUTHORIZATION_CODE_PARAMETER,
            None
        )

        await starsessions.load_session(conn)

        # First check if user is already logged in through the session
        if conn.session.get(self.USER_SESSION_KEY, None):
            user_session_info = conn.session.get(self.USER_SESSION_KEY)

            assert user_session_info is not None

            return AuthCredentials(), CognitoUser(
                user_session_info[self.ID_TOKEN_KEY][self.EMAIL_CLAIM_KEY],
                user_session_info[self.ID_TOKEN_KEY][self.COGNITO_GROUPS_KEY],
                user_session_info[self.GROUP_LOGIN_LINKS_KEY],
                user_session_info[self.ID_TOKEN_KEY]
                                 [self.FIRST_NAME_CLAIM_KEY],
                user_session_info[self.ID_TOKEN_KEY][self.LAST_NAME_CLAIM_KEY]

            )

        # If user is not logged in, check if we can log the user in through
        # an authorization code
        if authorization_code is None or authorization_code == "":
            return AuthCredentials(), UnauthenticatedUser()

        service_container = conn.app.state.service_container
        client_id = service_container.config.cognito_client_id()
        redirect_url = f"{service_container.config.app_base_url()}/"

        # If there is an authorization code, check if we used it before
        cached_tokens = self.get_tokens_from_cache_by_authorization_code(
            authorization_code
        )

        # If we have not used the authorization code: obtain tokens
        if not cached_tokens:
            session_key = service_container.config.session_pkce_secret_key()
            code_verifier = conn\
                .session[session_key][self.CODE_VERIFIER_PARAMETER]
            token_request_data = {
                self.GRANT_TYPE_PARAMETER:
                    TokenRequestGrantTypes.AUTHORIZATION_CODE.value,
                self.AUTHORIZATION_CODE_PARAMETER: authorization_code,
                self.CLIENT_ID_PARAMETER: client_id,
                self.REDIRECT_URI_PARAMETER: redirect_url,
                self.CODE_VERIFIER_PARAMETER: code_verifier
            }

            token_response = requests.post(
                self._cognito_service.get_token_endpoint(),
                data=token_request_data
            )

            parsed_response = token_response.json()
            self._cache.set(authorization_code, parsed_response)
        else:
            # Use the cached tokens if we used the authorization code before
            parsed_response = cached_tokens

        access_token = parsed_response[self.ACCESS_TOKEN_KEY]
        id_token = parsed_response[self.ID_TOKEN_KEY]

        # Validate all the tokens before we use them, to prevent token forgery
        valid_id_token = self._token_verifier.is_valid_id_token(
            id_token,
            access_token
        )
        valid_access_token = self._token_verifier.is_valid_access_token(
            access_token
        )

        are_valid_tokens = [
            valid_access_token,
            valid_id_token
        ]

        if all(are_valid_tokens):
            decoded_id_token = self._token_verifier.decode_id_token(
                id_token,
                access_token
            )

            identity_pool_identity_id = \
                self._cognito_service.get_cognito_identity_id(id_token)

            open_id_token = self._cognito_service.get_open_id_token(
                identity_pool_identity_id,
                id_token
            )

            assert decoded_id_token is not None

            group_role_mapping = self._cognito_service.get_roles_by_groups(
                decoded_id_token[self.COGNITO_GROUPS_KEY]
            )

            group_login_link_mapping = dict()

            for group, role in group_role_mapping.items():
                login_link = self._aws_console_service.\
                    get_console_url_by_openid_token(
                        role,
                        open_id_token,
                        decoded_id_token[self.EMAIL_CLAIM_KEY]
                    )
                group_login_link_mapping[group] = login_link

            # By now we've done all token exchanges, hence we can save the
            # info in the session for re-use
            user_session_info = {
              self.ID_TOKEN_KEY: decoded_id_token,
              "group_login_link_mapping": group_login_link_mapping
            }

            conn.session[self.USER_SESSION_KEY] = user_session_info

            return AuthCredentials(), CognitoUser(
                decoded_id_token[self.EMAIL_CLAIM_KEY],
                decoded_id_token[self.COGNITO_GROUPS_KEY],
                group_login_link_mapping,
                decoded_id_token.get(self.FIRST_NAME_CLAIM_KEY, ""),
                decoded_id_token[self.LAST_NAME_CLAIM_KEY]
            )
        else:
            return AuthCredentials(), UnauthenticatedUser()

    def get_tokens_from_cache_by_authorization_code(
        self,
        authorization_code: str
    ) -> dict | NoValue:
        cache_value = self._cache.get(authorization_code)

        return cache_value
