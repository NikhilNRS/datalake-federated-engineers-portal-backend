from typing import Optional

import requests
from jose import JWTError, jwt
from jose.backends.cryptography_backend import CryptographyRSAKey
from starlette.authentication import AuthenticationBackend, AuthCredentials, \
    BaseUser, UnauthenticatedUser, SimpleUser
from starlette.requests import HTTPConnection

from models.enums import TokenRequestGrantTypes, TokenUseTypes
from services.cognito import CognitoService


class TokenVerificationService:
    VALID_TOKEN_TYPES = [TokenUseTypes.ACCESS_TOKEN, TokenUseTypes.ID_TOKEN]

    def __init__(self, cognito_service: CognitoService):
        self._cognito_service = cognito_service

    # TODO: Split logic for verifying access tokens and id_tokens
    def is_valid_token(
        self,
        token_to_validate: str,
    ) -> bool:
        decoded_token = self.decode_token(token_to_validate)
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

    def decode_token(self, token: str) -> Optional[dict]:
        try:
            token_header = jwt.get_unverified_header(token)
            token_payload = jwt.get_unverified_claims(token)

            token_key_id = token_header.get("kid")
            cognito_key = self._get_json_web_key(token_key_id)
            token_use_type = self._get_token_use_type(token_payload)
            cognito_client_id = self._cognito_service.get_user_pool_client(
                self._get_client_id_from_token(token_payload)
            )

            if token_use_type == TokenUseTypes.ID_TOKEN:
                # TODO: Provide access_token as additional parameter so that
                #  the at_hash claim of the id_token can be verified
                decoded_token = jwt.decode(
                    token=token,
                    key=cognito_key.to_dict(),
                    audience=cognito_client_id,
                    algorithms=cognito_key.to_dict().get("alg"),
                    issuer=self._cognito_service.get_issuer_url()
                )
            else:
                decoded_token = jwt.decode(
                    token=token,
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

    def __init__(
        self,
        token_verification_service: TokenVerificationService,
        cognito_service: CognitoService
    ):
        self._token_verifier = token_verification_service
        self._cognito_service = cognito_service

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
        access_token = parsed_response[self.ACCESS_TOKEN_KEY]
        id_token = parsed_response[self.ID_TOKEN_KEY]

        are_valid_tokens = []

        for token in (access_token, id_token):
            are_valid_tokens.append(
                self._token_verifier.is_valid_token(token)
            )

        if all(are_valid_tokens):
            decoded_id_token = self._token_verifier.decode_token(id_token)
            # TODO: Save access_token + refresh_token in server_side session.
            #  Perhaps using or a fork thereof:
            #  https://github.com/auredentan/starlette-session/

            return AuthCredentials(), SimpleUser(
                decoded_id_token[self.EMAIL_CLAIM_KEY]
            )
