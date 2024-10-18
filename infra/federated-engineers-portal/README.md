# FDE Portal Backend Infrastructure

This app deploys the infrastructure components for cognito solution for federated engineers including permissions for the various FDE roles.

## Deployment Flow with the separate repo setup of Infra and Source Code

- Infra stack creates all the necessary components
- To deploy the Apprunner service as the initial setup a dummy docker image is used as source
- Once the stack is deployed and merged, the AppRunnerURL in cdk.context.json needs to be updated
  with the actual Apprunner instance deployed in a following PR
- From the datalake-federated-engineers-portal-backend repo, deploy the actual application code docker image via the CI/CD pipeline
- Update the ecr_image_tag variable in cdk.context.json with the tag version deployed in above step in a separate PR
