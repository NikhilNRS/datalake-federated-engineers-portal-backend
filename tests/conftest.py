# tests/conftest.py

import os

def pytest_configure():
    """Set environment variables before any tests are collected or run."""
    os.environ["COGNITO_CLIENT_ID"] = "bens-client-id"
    os.environ["COGNITO_USER_POOL_DOMAIN"] = "bens-user-pool-domain"
    os.environ["COGNITO_USER_POOL_ID"] = "bens-user-pool-id"
    os.environ["COGNITO_IDENTITY_POOL_ID"] = "bens-identity-pool-id"
    os.environ["AWS_REGION"] = "eu-test-1"
    os.environ["APP_ENV"] = "dev"
