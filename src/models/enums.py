import enum


class TokenRequestGrantTypes(enum.Enum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"


class AuthorizeRequestResponseTypes(enum.Enum):
    AUTHORIZATION_CODE = "code"
    TOKEN = "token"


class TokenUseTypes(enum.Enum):
    ID_TOKEN = "id"
    ACCESS_TOKEN = "access"
