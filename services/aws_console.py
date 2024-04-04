import json
import urllib.parse
from typing import Optional

import requests
from botocore.client import BaseClient
from requests import PreparedRequest


class AWSConsoleService:
    _STS_CREDENTIALS_KEY = "Credentials"
    _REQUIRED_KEYS_FOR_URL = [
        "AccessKeyId",
        "SecretAccessKey",
        "SessionToken"
    ]
    _URL_KEY_MAPPING = {
        "AccessKeyId": "sessionId",
        "SecretAccessKey": "sessionKey",
        "SessionToken": "sessionToken"
    }

    _AWS_CONSOLE_FEDERATION_ENDPOINT = \
        "https://signin.aws.amazon.com/federation"

    _AWS_CONSOLE_MAIN_ENDPOINT = "https://console.aws.amazon.com/"

    _SIGNIN_TOKEN_KEY = "SigninToken"
    _ACTION_PARAM = "Action"
    _SESSION_DURATION_PARAM = "SessionDuration"
    _SESSION_PARAM = "Session"
    _ISSUER_PARAM = "Issuer"
    _DESTINATION_PARAM = "Destination"

    def __init__(self, sts_client: BaseClient, app_base_url: str):
        self._sts_client = sts_client
        self._base_url = app_base_url

    def get_console_url_by_openid_token(
        self,
        role_arn: str,
        openid_token: str,
        user_email: str
    ) -> Optional[str]:
        # Ensure we do not try to retrieve credentials when no role
        # is provided
        if role_arn is None:
            return None

        sts_credentials = self._sts_client.assume_role_with_web_identity(
            RoleArn=role_arn,
            RoleSessionName=user_email,
            WebIdentityToken=openid_token
        )[self._STS_CREDENTIALS_KEY]

        filtered_credentials_for_url = dict(
            filter(
                lambda item: item[0] in self._REQUIRED_KEYS_FOR_URL,
                sts_credentials.items()
            )
        )

        required_credentials_for_url = {
            self._URL_KEY_MAPPING[k]: v
            for k, v in filtered_credentials_for_url.items()
        }

        json_credentials = json.dumps(required_credentials_for_url)
        url_encoded_json_credentials = urllib.parse.quote_plus(
            json_credentials
        )

        query_params = {
            self._ACTION_PARAM: "getSigninToken",
            self._SESSION_DURATION_PARAM: 43200,
            self._SESSION_PARAM: json_credentials
        }

        response = requests.post(
            self._AWS_CONSOLE_FEDERATION_ENDPOINT,
            data=query_params
        )

        signin_token = response.json()[self._SIGNIN_TOKEN_KEY]

        signin_url_query_params = {
            self._ACTION_PARAM: "login",
            self._ISSUER_PARAM: self._base_url,
            self._DESTINATION_PARAM: self._AWS_CONSOLE_MAIN_ENDPOINT,
            self._SIGNIN_TOKEN_KEY: signin_token
        }

        prepared_request = PreparedRequest()
        prepared_request.prepare_url(
            self._AWS_CONSOLE_FEDERATION_ENDPOINT,
            signin_url_query_params
        )

        return prepared_request.url
