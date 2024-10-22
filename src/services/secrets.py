import json
import random
from base64 import urlsafe_b64encode
from hashlib import sha256
from logging import Logger
from string import ascii_letters, digits
from typing import Literal, Any

from botocore.exceptions import ClientError
from mypy_boto3_secretsmanager import SecretsManagerClient
from mypy_boto3_secretsmanager.type_defs import GetSecretValueResponseTypeDef

from models.pkce import PKCESecret


class SecretsService:
    _SECRET_STRING_KEY: Literal["SecretString"] = "SecretString"

    def __init__(
        self,
        secrets_manager_client: SecretsManagerClient,
        logger: Logger
    ):
        """Constructs a SecretsService

        :param secrets_manager_client: boto3 secrets manager client
        """

        self._client = secrets_manager_client
        self._logger = logger

    def get_secret_value(self, secret_name: str) -> str | None:
        """Retrieves a single secret value from secrets manager

        :param secret_name: name of the secret to retrieve
        :return: secret value as a string
        """
        return self._get_secret_response(secret_name=secret_name)

    def get_json_secret(self, secret_name: str) -> dict[str, Any]: 
        """Retrieves a json secret from secrets manager

        :param secret_name: name of the secret to retrieve
        :return: dictionary containing the parsed json values
        """
        secret = self._get_secret_response(secret_name)
        return json.loads(secret) if secret else None # type: ignore

    def _get_secret_response(self, secret_name: str) -> str | None:
        secret_response: GetSecretValueResponseTypeDef | None = None
        try:
            secret_response = self._client.get_secret_value(
                SecretId=secret_name
            )
        except ClientError as err:
            self._logger.error(err.with_traceback(None))

        if secret_response:
            return secret_response[self._SECRET_STRING_KEY]
        else:
            return None


class PKCESecretGenerator:
    def __init__(self, random_str_generator: random.Random):
        """Creates a PKCE Secret generator

        :param random_str_generator: A cryptographically strong random
        number generator
        """
        self._random_generator = random_str_generator

    def generate_pkce_secret(self) -> PKCESecret:
        character_set = ascii_letters + digits
        random_chars = self._random_generator.choices(character_set, k=128)
        code_verifier = "".join(random_chars)
        code_verifier_hash = sha256(code_verifier.encode()).digest()
        code_challenge = urlsafe_b64encode(code_verifier_hash)\
            .decode()\
            .rstrip("=")

        return PKCESecret(
            code_verifier=code_verifier,
            code_verifier_hash=code_verifier_hash,
            code_challenge=code_challenge
        )
