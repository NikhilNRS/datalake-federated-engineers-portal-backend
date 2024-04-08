from typing import Optional

import requests
from dogpile.cache import CacheRegion
from jose import JWTError, jwt
from jose.backends.cryptography_backend import CryptographyRSAKey
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
            cognito_client_id = self._cognito_service.get_user_pool_client(
                self._get_client_id_from_token(token_payload)
            )

            decoded_token = jwt.decode(
                token=id_token,
                key=cognito_key.to_dict(),
                audience=cognito_client_id,
                algorithms=cognito_key.to_dict().get("alg"),
                issuer=self._cognito_service.get_issuer_url(),
                access_token=access_token
            )
        except JWTError as e:
            return None

        return decoded_token

    def decode_access_token(self, access_token: str) -> Optional[dict]:
        try:
            token_header = jwt.get_unverified_header(access_token)
            token_key_id = token_header.get("kid")
            cognito_key = self._get_json_web_key(token_key_id)

            decoded_token = jwt.decode(
                token=access_token,
                key=cognito_key.to_dict(),
                algorithms=cognito_key.to_dict().get("alg"),
                issuer=self._cognito_service.get_issuer_url()
            )
        except JWTError as e:
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

    def _get_json_web_key(self, key_id) -> Optional[CryptographyRSAKey]:
        return self._cognito_service.get_json_web_key(key_id)

    def _has_valid_token_type(self, token_type: str):
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
    ACCESS_TOKEN_KEY = "access_token"
    ID_TOKEN_KEY = "id_token"
    EMAIL_CLAIM_KEY = "email"
    COGNITO_GROUPS_KEY = "cognito:groups"
    FIRST_NAME_CLAIM_KEY = "given_name"
    LAST_NAME_CLAIM_KEY = "family_name"

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

        if authorization_code is None or authorization_code == "":
            return AuthCredentials(), UnauthenticatedUser()

        # TODO: Perhaps use PKCE with codes, to make it safer:
        #  https://docs.aws.amazon.com/cognito/latest/developerguide/using-pkce-in-authorization-code.html
        service_container = conn.app.state.service_container
        client_id = service_container.config.cognito_client_id()
        redirect_url = f"{service_container.config.app_base_url()}/"

        cached_tokens = self.get_tokens_from_cache_by_authorization_code(
            authorization_code
        )

        if not cached_tokens:
            token_request_data = {
                self.GRANT_TYPE_PARAMETER:
                    TokenRequestGrantTypes.AUTHORIZATION_CODE.value,
                self.AUTHORIZATION_CODE_PARAMETER: authorization_code,
                self.CLIENT_ID_PARAMETER: client_id,
                self.REDIRECT_URI_PARAMETER: redirect_url
            }

            token_response = requests.post(
                self._cognito_service.get_token_endpoint(),
                data=token_request_data
            )

            parsed_response = token_response.json()
            self._cache.set(authorization_code, parsed_response)
        else:
            parsed_response = cached_tokens

        access_token = parsed_response[self.ACCESS_TOKEN_KEY]
        id_token = parsed_response[self.ID_TOKEN_KEY]

        valid_id_token = self._token_verifier.is_valid_id_token(
            id_token,
            access_token
        )

        are_valid_tokens = [
            self._token_verifier.is_valid_access_token(access_token),
            valid_id_token
        ]

        if all(are_valid_tokens):
            decoded_id_token = self._token_verifier.decode_id_token(
                id_token,
                access_token
            )
            # TODO: Save access_token + refresh_token in server_side session.
            #  Perhaps using or a fork thereof:
            #  https://github.com/auredentan/starlette-session/

            # TODO: Add more user data
            identity_pool_identity_id = \
                self._cognito_service.get_cognito_identity_id(id_token)

            open_id_token = self._cognito_service.get_open_id_token(
                identity_pool_identity_id,
                id_token
            )

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

            return AuthCredentials(), CognitoUser(
                decoded_id_token[self.EMAIL_CLAIM_KEY],
                decoded_id_token[self.COGNITO_GROUPS_KEY],
                group_login_link_mapping,
                decoded_id_token[self.FIRST_NAME_CLAIM_KEY],
                decoded_id_token[self.LAST_NAME_CLAIM_KEY]
            )

    def get_tokens_from_cache_by_authorization_code(
        self,
        authorization_code: str
    ) -> dict:
        cache_value = self._cache.get(authorization_code)

        return cache_value
