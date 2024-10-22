import urllib.parse
from logging import Logger
from typing import Union, Tuple

import redis
from botocore.signers import RequestSigner


class ElasticacheIAMProvider(redis.CredentialProvider):
    def __init__(
        self,
        user: str,
        cluster_name: str,
        request_signer: RequestSigner,
        logger: Logger
    ):
        self._user = user
        self._cluster_name = cluster_name
        self._request_signer = request_signer
        self._region = request_signer.region_name
        self._logger = logger

    def get_credentials(self) -> Union[Tuple[str], Tuple[str, str]]:
        query_params = {
            "Action": "connect",
            "User": self._user
        }

        parse_result = urllib.parse.ParseResult(
            scheme="http",
            netloc=self._cluster_name,
            path="/",
            query=urllib.parse.urlencode(query_params),
            params="",
            fragment=""
        )

        url = urllib.parse.urlunparse(parse_result)

        request_dict = {
            "method": "GET",
            "url": url,
            "body": {},
            "headers": {},
            "context": {}
        }

        signed_url = self._request_signer.generate_presigned_url(
            request_dict=request_dict,
            operation_name="connect",
            expires_in=900,
            region_name=self._region
        )

        # RequestSigner only seems to work if the URL has a protocol, but
        # Elasticache only accepts the URL without a protocol
        # So strip it off the signed URL before returning
        self._logger.debug(
            f"The current redis_user is: {self._user}\n"
            f'The signed_url is: '
            f'{signed_url.removeprefix("http://")}'
        )

        return self._user, signed_url.removeprefix("http://")
