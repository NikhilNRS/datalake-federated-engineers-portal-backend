# Changelog

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
