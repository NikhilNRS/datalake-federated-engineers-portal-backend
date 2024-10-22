#!/usr/bin/env node
import 'source-map-support/register';
import { CognitoStack } from './cognito/stack';
import 'dotenv/config';
import { App, Aspects } from "aws-cdk-lib";
import { PermissionsBoundaryAspect, getContextVariable } from "@datalake/dl-utils";
import * as process from "node:process";

const app = new App();

const stage = app.node.getContext("stage");
const apprunnerURLs = getContextVariable(stage, "AppRunnerURL");


new CognitoStack(app, `${stage}-CognitoStack`.toLowerCase(), {
    name: "federated-engineers",
    stage: stage,
    access_token_duration: 3600,
    refresh_token_duration: 7200,
    id_token_duration: 3600,
    federated_idp: "onewelcome",
    federated_idp_saml_metadata_url: "https://www.loginpostnl.net/am/saml2/jsp/exportmetadata.jsp?entityid=https://www.loginpostnl.net:443/am4k",
    appRunnerURL: apprunnerURLs,
    env: {
        account: process.env.CDK_DEFAULT_ACCOUNT,
        region: process.env.CDK_DEFAULT_REGION,
    },
    image_tag: getContextVariable(stage, "ecr_image_tag"),
});

Aspects.of(app).add(new PermissionsBoundaryAspect());
