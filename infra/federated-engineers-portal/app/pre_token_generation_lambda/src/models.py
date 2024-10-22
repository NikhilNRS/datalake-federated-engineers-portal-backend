from typing import Optional, Any

from pydantic import BaseModel


class CallerContext(BaseModel):
    awsSdkVersion: str
    clientId: str


class GroupConfiguration(BaseModel):
    groupsToOverride: list[str]
    iamRolesToOverride: list[str]
    preferredRole: Optional[str]


class Request(BaseModel):
    userAttributes: dict[str, str]
    groupConfiguration: GroupConfiguration
    clientMetadata: Optional[dict[str, Any]] = None


class ClaimsOverrideDetails(BaseModel):
    claimsToAddOrOverride: Optional[dict[str, str]]
    claimsToSuppress: Optional[list[str]]
    groupOverrideDetails: Optional[GroupConfiguration]


class Response(BaseModel):
    claimsOverrideDetails: Optional[ClaimsOverrideDetails]


class PreTokenGenerationV1Event(BaseModel):
    version: str
    triggerSource: str
    region: str
    userPoolId: str
    userName: str
    callerContext: CallerContext
    request: Request
    response: Response
