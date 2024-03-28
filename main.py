import toml
import uvicorn
from dotenv import load_dotenv
import fastapi
from fastapi import Security, Request
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import FileResponse

from dependency_injection.container import ServiceContainer
from dependency_injection.fast_api import check_user_login

load_dotenv()

API_VERSION = toml.load("pyproject.toml")["tool"]["poetry"]["version"]
API_DESCRIPTION = toml.load("pyproject.toml")["tool"]["poetry"]["description"]

app = fastapi.FastAPI(
    title="PostNL - Federated Engineers login portal",
    descripton=API_DESCRIPTION,
    version=API_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

# Initialize service container for dependency injection
app.state.service_container = ServiceContainer()
# noinspection PyTypeChecker
app.add_middleware(
    AuthenticationMiddleware,
    backend=app.state.service_container.authorization_code_backend()
)


@app.get(
    "/",
    dependencies=[
        Security(check_user_login, scopes=[])
    ]
)
def home(request: Request):
    return f"Welcome to the portal!\nYou're logged in as: " \
           f"{request.user.username}"

# TODO: The redirect works so far, however, I am stumbling upon an error 13:
#  https://postnl.atlassian.net/wiki/spaces/IAM/pages/3487989895/Er+is+iets+misgegaan+met+inloggen+Error+13
#  To solve it we might need to request help from the IAM team, through TopDesk


@app.get("/favicon.ico", include_in_schema=False)
def get_favicon():
    return FileResponse("assets/favicon.ico")


if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000)
