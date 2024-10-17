import pytest
from ..src.main import lambda_handler


@pytest.mark.parametrize("input_schema",[
    {
        "version": "1",
        "triggerSource": "TokenGeneration_HostedAuth",
        "region": "eu-test-56",
        "userPoolId": "eu-test-56_T4QRandom",
        "userName": "myIdProvider_1234",
        "callerContext": {
          "awsSdkVersion": "aws-sdk-test-test",
          "clientId": "myTestClientId1234"
        },
        "request": {
            "userAttributes": {"name": "tester"},
            "groupConfiguration": {
                "groupsToOverride": ["group1", "group2"],
                "iamRolesToOverride": [],
                "preferredRole": ""
            },
            "clientMetadata": {}
        },
        "response": {
            "claimsOverrideDetails": {
                "claimsToAddOrOverride": {},
                "claimsToSuppress": [],
                "groupOverrideDetails": {
                    "groupsToOverride": [],
                    "iamRolesToOverride": [],
                    "preferredRole": ""
                }
            }
        }
    },
    {
        "version": "1",
        "triggerSource": "TokenGeneration_HostedAuth",
        "region": "eu-test-56",
        "userPoolId": "eu-test-56_T4QRandom",
        "userName": "myIdProvider_1234",
        "callerContext": {
          "awsSdkVersion": "aws-sdk-test-test",
          "clientId": "myTestClientId1234"
        },
        "request": {
            "userAttributes": {"name": "tester"},
            "groupConfiguration": {
                "groupsToOverride": ["group1", "group2"],
                "iamRolesToOverride": [],
                "preferredRole": ""
            },
            "clientMetadata": {}
        },
        "response": {
            "claimsOverrideDetails": None
        }
    }
])
def test_lambda(input_schema):
    output = lambda_handler(input_schema, {})

    assert "user_groups" in output["response"]["claimsOverrideDetails"]["claimsToAddOrOverride"]

    assert output["response"]["claimsOverrideDetails"]["claimsToAddOrOverride"]["user_groups"] == ":group1:group2:"

