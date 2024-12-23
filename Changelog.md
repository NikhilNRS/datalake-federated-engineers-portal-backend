# Changelog

## 1.0.0 - 31-10-2024

- DLAK-2343 - Implement application deployment and updates via Infra pipeline

## 0.1.9 - 30-10-2024

- DLAK-2343 - move infra to this (datalake-federated-engineers-portal-backend) repo.

## 0.1.8 - 30-08-2024

- DLAK-2468 - Add unit tests for CognitoService class and configure CI/CD pipeline for automated testing using GitHub Actions.

## 0.1.7 - 07-08-2024

- Replace PyJWT git dependency with regular pypi based one

## 0.1.6 - 01-08-2024

- Fix various linting and mypy errors
- Add `utils/urls.py` for easy switching between aws and local env.

## 0.1.5 - 30-07-2024

- Add logging to fastapi dependency

## 0.1.4 - 25-07-2024

- DLAK-2081 - Add logout endpoint to fde-portal

## 0.1.3 - 22-07-2024

- DLAK-1223 - Raise error when an invalid app_env value is provided
- Enable CI/CD pipeline in repo for deployments

## 0.1.2 - 08-07-2024

- DLAK-2303 - Make smarter use of fastapi to format APP_BASE_URL, so that the
  env variable is no longer needed.

## 0.1.1 - 19-06-2024

- DLAK-2034 - Fix bug where login links did not appear
- Add Changelog

## 0.1.0 - 23-05-2024

Initial version with the following features:

- Login to AWS Console through OneWelcome with limited access roles assigned
  to Cognito Groups
- Server-Side Sessions
- Redis Caching
- Replace `python-jose` with `PyJWT` due to security vulnerabilities
- Full mypy compliance
