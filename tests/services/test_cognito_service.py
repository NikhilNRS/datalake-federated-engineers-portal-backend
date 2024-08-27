import pytest
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

@pytest.fixture
def cognito_service():
    """Fixture to create a CognitoService instance with stubbed clients."""
    # Environment variables are set in conftest.py, so we can use them here
    container = ServiceContainer()

    boto3_session = Session(region_name=os.environ["AWS_REGION"])

    cognito_idp_client = boto3_session.client("cognito-idp")
    cognito_identity_client = boto3_session.client("cognito-identity")

    mock_cache = make_region().configure('dogpile.cache.memory')
    mock_logger = Mock()

    container.aws_cognito_client.override(providers.Object(cognito_idp_client))
    container.aws_cognito_identity_client.override(providers.Object(cognito_identity_client))
    container.dogpile_cache_region.override(providers.Object(mock_cache))
    container.logger.override(providers.Object(mock_logger))

    cognito_service_instance = container.cognito_service()

    yield cognito_service_instance

@pytest.fixture
def mock_cache():
    """Fixture to create an in-memory cache."""
    return make_region().configure('dogpile.cache.memory')

# Define test functions
def test_get_issuer_url(cognito_service):
    """Test the get_issuer_url method of CognitoService."""
    result = cognito_service.get_issuer_url()
    expected_url = f"https://cognito-idp.{os.environ['AWS_REGION']}.amazonaws.com/{os.environ['COGNITO_USER_POOL_ID']}"
    assert result == expected_url

def test_get_issuer_host_name(cognito_service):
    """Test the get_issuer_host_name method of CognitoService."""
    result = cognito_service.get_issuer_host_name()
    expected_hostname = f"cognito-idp.{os.environ['AWS_REGION']}.amazonaws.com/{os.environ['COGNITO_USER_POOL_ID']}"
    assert result == expected_hostname

def test_get_json_web_key(cognito_service, mock_cache):
    """Test the get_json_web_key method of CognitoService."""
    key_id = "example-key-id"

    cognito_service._cache_client.get = Mock(return_value=None)
    cognito_service._refresh_user_pool_json_web_keys = Mock()

    result = cognito_service.get_json_web_key(key_id)
    cognito_service._cache_client.get.assert_called_with(f"kid_{key_id}")
    cognito_service._refresh_user_pool_json_web_keys.assert_called_once()

def test_get_authorize_endpoint(cognito_service):
    """Test the get_authorize_endpoint method of CognitoService."""
    result = cognito_service.get_authorize_endpoint()
    expected_endpoint = f"https://{os.environ['COGNITO_USER_POOL_DOMAIN']}.auth.{os.environ['AWS_REGION']}.amazoncognito.com/oauth2/authorize"
    assert result == expected_endpoint

def test_get_token_endpoint(cognito_service):
    """Test the get_token_endpoint method of CognitoService."""
    result = cognito_service.get_token_endpoint()
    expected_endpoint = f"https://{os.environ['COGNITO_USER_POOL_DOMAIN']}.auth.{os.environ['AWS_REGION']}.amazoncognito.com/oauth2/token"
    assert result == expected_endpoint

def test_get_logout_endpoint(cognito_service):
    """Test the get_logout_endpoint method of CognitoService."""
    redirect_uri = "https://example.com/logout"
    result = cognito_service.get_logout_endpoint(redirect_uri)

    # Use quote_plus to ensure encoding matches the method output
    expected_endpoint = f"https://{os.environ['COGNITO_USER_POOL_DOMAIN']}.auth.{os.environ['AWS_REGION']}.amazoncognito.com/logout?client_id={os.environ['COGNITO_CLIENT_ID']}&logout_uri={urllib.parse.quote_plus(redirect_uri)}"
    assert result == expected_endpoint

def test_get_user_pool_client(cognito_service):
    """Test the get_user_pool_client method of CognitoService."""
    client_id = "example-client-id"

    cognito_service._cache_client.get = Mock(return_value=None)

    with Stubber(cognito_service._cognito_client) as stubber:
        stubber.add_response(
            'describe_user_pool_client',
            {'UserPoolClient': {'ClientId': client_id}},
            {'UserPoolId': os.environ['COGNITO_USER_POOL_ID'], 'ClientId': client_id}
        )

        result = cognito_service.get_user_pool_client(client_id)
        assert result == client_id

def test_get_cognito_identity_id(cognito_service):
    """Test the get_cognito_identity_id method of CognitoService."""
    id_token = "example-id-token"

    with Stubber(cognito_service._cognito_identity_client) as stubber:
        stubber.add_response(
            'get_id',
            {'IdentityId': 'eu-test-1:example-id'},
            {'IdentityPoolId': os.environ['COGNITO_IDENTITY_POOL_ID'], 'Logins': {cognito_service.get_issuer_host_name(): id_token}}
        )

        result = cognito_service.get_cognito_identity_id(id_token)
        assert result == 'eu-test-1:example-id'

def test_get_open_id_token(cognito_service):
    """Test the get_open_id_token method of CognitoService."""
    cognito_identity_id = "example-identity-id"
    id_token = "example-id-token"

    with Stubber(cognito_service._cognito_identity_client) as stubber:
        stubber.add_response(
            'get_open_id_token',
            {'Token': 'example-open-id-token'},
            {'IdentityId': cognito_identity_id, 'Logins': {cognito_service.get_issuer_host_name(): id_token}}
        )

        result = cognito_service.get_open_id_token(cognito_identity_id, id_token)
        assert result == 'example-open-id-token'

def test_get_roles_by_groups(cognito_service):
    """Test the get_roles_by_groups method of CognitoService."""
    group_names = ['group1', 'group2']

    with Stubber(cognito_service._cognito_client) as stubber:
        stubber.add_response(
            'get_group',
            {'Group': {'GroupName': 'group1', 'RoleArn': 'arn:aws:iam::123456789012:role/role-arn-1'}},
            {'GroupName': 'group1', 'UserPoolId': os.environ['COGNITO_USER_POOL_ID']}
        )
        stubber.add_response(
            'get_group',
            {'Group': {'GroupName': 'group2', 'RoleArn': 'arn:aws:iam::123456789012:role/role-arn-2'}},
            {'GroupName': 'group2', 'UserPoolId': os.environ['COGNITO_USER_POOL_ID']}
        )

        result = cognito_service.get_roles_by_groups(group_names)
        expected_result = {'group1': 'arn:aws:iam::123456789012:role/role-arn-1', 'group2': 'arn:aws:iam::123456789012:role/role-arn-2'}
        assert result == expected_result
