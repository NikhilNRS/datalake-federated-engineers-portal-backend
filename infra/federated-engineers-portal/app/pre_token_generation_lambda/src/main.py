import logging
import sys

from pydantic import ValidationError

from .models import PreTokenGenerationV1Event, ClaimsOverrideDetails

logger = logging.getLogger()
handler = logging.StreamHandler(sys.stdout)
logger.addHandler(handler)
logger.setLevel(logging.INFO)


def lambda_handler(event: dict, context):
    """The Pre-TokenGeneration Lambda for the Cognito User Pool. Basically it flattens the JSON Array with Cognito
       groups to a space-separated string with the same information, to prevent an Authorization Error on STS, as STS
       cannot handle json arrays, nor escaped string-representations thereof.

    @param event: Lambda Event following the structure described here:
           https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html#cognito-user-pools-lambda-trigger-syntax-pre-token-generation
    @param context: required, but unnecessary parameter
    @return: Modified event
    """
    logger.info("generating pre-token generation event")

    try:
        logger.info(f"input event: {event}")
        parsed_event = PreTokenGenerationV1Event(**event)
        cognito_groups_array = parsed_event.request.groupConfiguration.groupsToOverride

        flattened_groups_str = ":" + ":".join(cognito_groups_array) + ":"
        user_group_claim = {
            "user_groups": flattened_groups_str
        }

        if parsed_event.response.claimsOverrideDetails is None:
            parsed_event.response.claimsOverrideDetails = ClaimsOverrideDetails(
                claimsToAddOrOverride=user_group_claim,
                claimsToSuppress=None,
                groupOverrideDetails=None
            )
        elif parsed_event.response.claimsOverrideDetails.claimsToAddOrOverride is not None:
            current_claims = parsed_event.response.claimsOverrideDetails.claimsToAddOrOverride
            new_claims = {**current_claims, **user_group_claim}
            parsed_event.response.claimsOverrideDetails.claimsToAddOrOverride = new_claims
        else:
            current_claims_to_suppress = parsed_event.response.claimsOverrideDetails.claimsToSuppress
            current_group_override_details = parsed_event.response.claimsOverrideDetails.groupOverrideDetails
            parsed_event.response.claimsOverrideDetails = ClaimsOverrideDetails(
                claimsToAddOrOverride=user_group_claim,
                claimsToSuppress=current_claims_to_suppress if current_claims_to_suppress is not None else None,
                groupOverrideDetails=current_group_override_details
                if current_group_override_details is not None else None
            )

        logger.info("token changes made successfully")

        logger.info(f"The returned event looks like this: {parsed_event.model_dump()}")

        return parsed_event.model_dump()
    except ValidationError as err:
        logger.info(f"Could not parse the following event:\n {event}")
        logger.error(err.with_traceback(None))

    return event
