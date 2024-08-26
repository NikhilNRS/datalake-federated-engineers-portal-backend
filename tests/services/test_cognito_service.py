import unittest
from unittest.mock import Mock
from botocore.stub import Stubber
from dependency_injector import providers
from dependency_injection.container import ServiceContainer
from boto3 import Session
from dogpile.cache import make_region
import jwt
import os
import urllib.parse

from services.cognito import CognitoService


class TestCognitoService(unittest.TestCase):
    def setUp(self):
        """Set up the environment using ServiceContainer with overrides."""

        # Environment variables are set in conftest.py, so we can use them here

        # Initialize ServiceContainer
        self.container = ServiceContainer()

        # Create real boto3 clients with stubbers
        boto3_session = Session(region_name=os.environ["AWS_REGION"])

        cognito_idp_client = boto3_session.client("cognito-idp")
        self.cognito_idp_stubber = Stubber(cognito_idp_client)
        self.cognito_idp_stubber.activate()

        cognito_identity_client = boto3_session.client("cognito-identity")
        self.cognito_identity_stubber = Stubber(cognito_identity_client)
        self.cognito_identity_stubber.activate()

        # Mock the cache region using an in-memory backend
        mock_cache = make_region().configure('dogpile.cache.memory')

        # Mock the logger
        mock_logger = Mock()

        # Override the providers in the container
        self.container.aws_cognito_client.override(providers.Object(cognito_idp_client))
        self.container.aws_cognito_identity_client.override(providers.Object(cognito_identity_client))
        self.container.dogpile_cache_region.override(providers.Object(mock_cache))
        self.container.logger.override(providers.Object(mock_logger))

        # Use the container to create the CognitoService instance
        self.cognito_service = self.container.cognito_service()

    def tearDown(self):
        """Deactivate stubs after tests."""
        self.cognito_idp_stubber.deactivate()
        self.cognito_identity_stubber.deactivate()

    def test_get_issuer_url(self):
        """Test the get_issuer_url method of CognitoService."""
        result = self.cognito_service.get_issuer_url()
        expected_url = f"https://cognito-idp.{os.environ['AWS_REGION']}.amazonaws.com/{os.environ['COGNITO_USER_POOL_ID']}"
        self.assertEqual(result, expected_url)

    def test_get_issuer_host_name(self):
        """Test the get_issuer_host_name method of CognitoService."""
        result = self.cognito_service.get_issuer_host_name()
        expected_hostname = f"cognito-idp.{os.environ['AWS_REGION']}.amazonaws.com/{os.environ['COGNITO_USER_POOL_ID']}"
        self.assertEqual(result, expected_hostname)

    def test_get_json_web_key(self):
        """Test the get_json_web_key method of CognitoService."""
        key_id = "example-key-id"

        # Mocking the cache to return None initially, simulating a cache miss
        self.cognito_service._cache_client.get = Mock(return_value=None)
        self.cognito_service._refresh_user_pool_json_web_keys = Mock()

        result = self.cognito_service.get_json_web_key(key_id)
        self.cognito_service._cache_client.get.assert_called_with(f"kid_{key_id}")
        self.cognito_service._refresh_user_pool_json_web_keys.assert_called_once()

    def test_get_authorize_endpoint(self):
        """Test the get_authorize_endpoint method of CognitoService."""
        result = self.cognito_service.get_authorize_endpoint()
        expected_endpoint = f"https://{os.environ['COGNITO_USER_POOL_DOMAIN']}.auth.{os.environ['AWS_REGION']}.amazoncognito.com/oauth2/authorize"
        self.assertEqual(result, expected_endpoint)

    def test_get_token_endpoint(self):
        """Test the get_token_endpoint method of CognitoService."""
        result = self.cognito_service.get_token_endpoint()
        expected_endpoint = f"https://{os.environ['COGNITO_USER_POOL_DOMAIN']}.auth.{os.environ['AWS_REGION']}.amazoncognito.com/oauth2/token"
        self.assertEqual(result, expected_endpoint)

    def test_get_logout_endpoint(self):
        """Test the get_logout_endpoint method of CognitoService."""
        redirect_uri = "https://example.com/logout"
        result = self.cognito_service.get_logout_endpoint(redirect_uri)

        # Use quote_plus to ensure encoding matches the method output
        expected_endpoint = f"https://{os.environ['COGNITO_USER_POOL_DOMAIN']}.auth.{os.environ['AWS_REGION']}.amazoncognito.com/logout?client_id={os.environ['COGNITO_CLIENT_ID']}&logout_uri={urllib.parse.quote_plus(redirect_uri)}"
        self.assertEqual(result, expected_endpoint)


    def test_get_user_pool_client(self):
        """Test the get_user_pool_client method of CognitoService."""
        client_id = "example-client-id"

        # Mocking the cache to return None initially
        self.cognito_service._cache_client.get = Mock(return_value=None)

        # Stubbing the AWS response
        self.cognito_idp_stubber.add_response(
            'describe_user_pool_client',
            {'UserPoolClient': {'ClientId': client_id}},
            {'UserPoolId': os.environ['COGNITO_USER_POOL_ID'], 'ClientId': client_id}
        )

        result = self.cognito_service.get_user_pool_client(client_id)
        self.assertEqual(result, client_id)

    def test_get_cognito_identity_id(self):
        """Test the get_cognito_identity_id method of CognitoService."""
        id_token = "example-id-token"

        # Stubbing the AWS response
        self.cognito_identity_stubber.add_response(
            'get_id',
            {'IdentityId': 'eu-test-1:example-id'},
            {'IdentityPoolId': os.environ['COGNITO_IDENTITY_POOL_ID'], 'Logins': {self.cognito_service.get_issuer_host_name(): id_token}}
        )

        result = self.cognito_service.get_cognito_identity_id(id_token)
        self.assertEqual(result, 'eu-test-1:example-id')

    def test_get_open_id_token(self):
        """Test the get_open_id_token method of CognitoService."""
        cognito_identity_id = "example-identity-id"
        id_token = "example-id-token"

        # Stubbing the AWS response
        self.cognito_identity_stubber.add_response(
            'get_open_id_token',
            {'Token': 'example-open-id-token'},
            {'IdentityId': cognito_identity_id, 'Logins': {self.cognito_service.get_issuer_host_name(): id_token}}
        )

        result = self.cognito_service.get_open_id_token(cognito_identity_id, id_token)
        self.assertEqual(result, 'example-open-id-token')

    def test_get_roles_by_groups(self):
        """Test the get_roles_by_groups method of CognitoService."""
        group_names = ['group1', 'group2']

        # Correct the stubbed response to match AWS expectations
        self.cognito_idp_stubber.add_response(
            'get_group',
            {'Group': {'GroupName': 'group1', 'RoleArn': 'arn:aws:iam::123456789012:role/role-arn-1'}},
            {'GroupName': 'group1', 'UserPoolId': os.environ['COGNITO_USER_POOL_ID']}
        )
        self.cognito_idp_stubber.add_response(
            'get_group',
            {'Group': {'GroupName': 'group2', 'RoleArn': 'arn:aws:iam::123456789012:role/role-arn-2'}},
            {'GroupName': 'group2', 'UserPoolId': os.environ['COGNITO_USER_POOL_ID']}
        )

        result = self.cognito_service.get_roles_by_groups(group_names)
        expected_result = {'group1': 'arn:aws:iam::123456789012:role/role-arn-1', 'group2': 'arn:aws:iam::123456789012:role/role-arn-2'}
        self.assertEqual(result, expected_result)


if __name__ == '__main__':
    unittest.main()
