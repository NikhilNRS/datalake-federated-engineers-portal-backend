from typing import Optional, Literal

import requests
from dogpile.cache import CacheRegion
from jose import jwk
from jose.backends.base import Key
from mypy_boto3_cognito_identity import CognitoIdentityClient
from mypy_boto3_cognito_idp import CognitoIdentityProviderClient


class CognitoService:
    _BASE_URL_TEMPLATE = "https://cognito-idp.{aws_region}.amazonaws.com/" \
                         "{user_pool_id}"
    _COGNITO_USER_POOL_BASE_URL_TEMPLATE = "https://{user_pool_domain}.auth." \
                                           "{aws_region}.amazoncognito.com"
    _IDENTITY_POOL_IDENTITY_ID_KEY: Literal["IdentityId"] = "IdentityId"
    _OPEN_ID_TOKEN_KEY: Literal["Token"] = "Token"
    _COGNITO_GROUP_KEY: Literal["Group"] = "Group"
    _ROLE_ARN_KEY: Literal["RoleArn"] = "RoleArn"

    def __init__(
        self,
        cognito_api_client: CognitoIdentityProviderClient,
        cognito_identity_api_client: CognitoIdentityClient,
        cache_client: CacheRegion,
        aws_region: str,
        user_pool_domain: str,
        user_pool_id: str,
        identity_pool_id: str
    ):
        self._cognito_client = cognito_api_client
        self._cognito_identity_client = cognito_identity_api_client
        self._cache_client = cache_client
        self._aws_region = aws_region
        self._user_pool_domain = user_pool_domain
        self._user_pool_id = user_pool_id
        self._identity_pool_id = identity_pool_id

    def _get_cognito_user_pool_base_url(self):
        """Returns the base url for the Cognito user pool that handles
        OAuth2 and SAML responses.

        :return: Base URL for the Cognito user pool
        """
        return self._COGNITO_USER_POOL_BASE_URL_TEMPLATE.format(
            user_pool_domain=self._user_pool_domain,
            aws_region=self._aws_region
        )

    def _get_base_url(self) -> str:
        """Generates the base url for the Cognito user pool. Mostly used to
        obtain data on the user pool itself.

        :return: the base url for the Cognito user pool
        """
        return self._BASE_URL_TEMPLATE.format(
            aws_region=self._aws_region,
            user_pool_id=self._user_pool_id
        )

    def get_issuer_url(self):
        """The URL embedded in access tokens that indicates where the
        access token was generated.

        :return: the issuer URL
        """
        return self._get_base_url()

    def get_issuer_host_name(self):
        return self.get_issuer_url().removeprefix("https://")

    def _get_json_web_keys_url(self) -> str:
        """The URL from which to obtain the current RSA public keys,
        used to sign access tokens

        :return: The RSA public keys in JSON Web Key (JWK) format
        """
        return f"{self._get_base_url()}/.well-known/jwks.json"

    def _refresh_user_pool_json_web_keys(self) -> None:
        """Ensures the cache contains the latest public RSA keys, that are
        used to sign Cognito access tokens.

        """
        # Get keys from Cognito
        url = self._get_json_web_keys_url()
        response = requests.get(url)

        # prepare dict with possible keys
        parsed_json = response.json()
        json_web_keys = {
            f'kid_{key["kid"]}': key
            for key in parsed_json["keys"]
        }

        # store keys in cache
        self._cache_client.set_multi(json_web_keys)

    def get_json_web_key(self, key_id: str) -> Optional[Key]:
        """All access tokens given out by AWS Cognito are cryptographically
        signed with an RSA Key pair. Cognito has 2 key pairs, that are
        regularly rotated. This method obtains the public key for the given
        key_id that can be used elsewhere to verify the cryptographic
        signature of an access_token (the key_id is embedded in the
        access_token). The public key is provided in json web key (JWK) format.

        :param key_id: The key_id of the public key to obtain.
        :return:The public key in JSON Web Key (JWK) format
        """
        # first check the cache
        cache_key_id = f"kid_{key_id}"
        result = self._cache_client.get(cache_key_id)

        # If not in cache refresh the cache and use the result
        if not result:
            self._refresh_user_pool_json_web_keys()
            result = self._cache_client.get(cache_key_id)

        try:
            assert isinstance(result, dict)
            return jwk.construct(result)
        except AssertionError:
            return None

    def get_authorize_endpoint(self):
        """Returns the OAuth2 authorize endpoint

        :return: the OAuth2 authorize endpoint
        """
        return f"{self._get_cognito_user_pool_base_url()}/oauth2/authorize"

    def get_token_endpoint(self):
        """Returns the OAuth2 token endpoint

        :return: the OAuth2 token endpoint
        """
        return f"{self._get_cognito_user_pool_base_url()}/oauth2/token"

    def get_user_pool_client(self, client_id: str) -> Optional[str]:
        """Retrieves additional information for a client from Cognito, but only
        saves the client_id. For now, We use this elsewhere to verify that a
        client_id in an access token actually exists in Cognito.

        :param client_id: The client_id to verify the existence of
        :return: The client_id we found in cognito, or None
         when the client does not exist.
        """
        client_cache_key = f"client_{client_id}"

        client = self._cache_client.get(client_cache_key)  # type: ignore

        if not client:
            try:
                client_response = \
                    self._cognito_client.describe_user_pool_client(
                        UserPoolId=self._user_pool_id,
                        ClientId=client_id
                    )
                self._cache_client.set(
                    client_cache_key,
                    client_response["UserPoolClient"]["ClientId"]
                )
                client = client_response["UserPoolClient"]["ClientId"]  # type: ignore # noqa: E501
            except self._cognito_client.exceptions.ResourceNotFoundException:
                return None
        assert isinstance(client, str)
        return client

    def get_cognito_identity_id(self, id_token: str) -> str:
        return self._cognito_identity_client.get_id(
            IdentityPoolId=self._identity_pool_id,
            Logins={
                self.get_issuer_host_name(): id_token
            }
        )[self._IDENTITY_POOL_IDENTITY_ID_KEY]

    def get_open_id_token(
        self,
        cognito_identity_id: str,
        id_token: str
    ) -> str:
        logins_dict = {
            self.get_issuer_host_name(): id_token
        }

        return self._cognito_identity_client.get_open_id_token(
            IdentityId=cognito_identity_id,
            Logins=logins_dict
        )[self._OPEN_ID_TOKEN_KEY]

    def get_roles_by_groups(
        self,
        group_names: list[str]
    ) -> dict[str, Optional[str]]:
        group_to_role_mapping = dict()

        for group_name in group_names:
            response = self._cognito_client.get_group(
                GroupName=group_name,
                UserPoolId=self._user_pool_id
            )
            group_to_role_mapping[group_name] = \
                response[self._COGNITO_GROUP_KEY].get(
                    self._ROLE_ARN_KEY,
                    None
                )

        return group_to_role_mapping
