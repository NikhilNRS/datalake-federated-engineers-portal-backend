from collections import Counter
import toml
import uvicorn
from dotenv import load_dotenv
import fastapi
from fastapi import Security, Request, HTTPException, status
from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starsessions import SessionMiddleware, regenerate_session_id

from dependency_injection.container import ServiceContainer
from dependency_injection.fast_api import check_user_login

# Load environment variables from .env file
load_dotenv()

API_VERSION = toml.load("pyproject.toml")["tool"]["poetry"]["version"]
API_DESCRIPTION = toml.load("pyproject.toml")["tool"]["poetry"]["description"]

app = fastapi.FastAPI(
    title="PostNL - Federated Engineers login portal",
    description=API_DESCRIPTION,
    version=API_VERSION,
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

# Initialize service container for dependency injection
app.state.service_container = ServiceContainer()

test_logger = app.state.service_container.logger()
# Test to see if logger shows output, especially on AWS
test_logger.info("Starting the FastAPI app!")

# Add endpoint for static files
app.mount("/static", StaticFiles(directory="./assets"), name="static")
templates = Jinja2Templates(
    directory="./jinja_templates",
    autoescape=False
)

# Be aware: The authentication middleware requires the session middleware to
# be loaded. However, add_middleware loads middleware in reverse. Hence,
# authentication middleware comes first.
# noinspection PyTypeChecker
app.add_middleware(
    AuthenticationMiddleware,
    backend=app.state.service_container.authorization_code_backend()
)

# noinspection PyTypeChecker
app.add_middleware(
    SessionMiddleware,
    store=app.state.service_container.dogpile_session_store(),
    lifetime=3600
)

@app.get(
    "/",
    dependencies=[
        Security(check_user_login, scopes=[])
    ]
)
def home(request: Request):
    # we check here how many cognito groups actually have a login link
    # (i.e. a role assigned). If none have a login link, we show a different
    # message on the home page

    login_links_counts = Counter(request.user.login_links.values())
    user_has_no_login_links = \
        login_links_counts.get(None) == len(request.user.login_links)

    page_content = {
        "title": f"{request.app.title} - Home",
        "first_name": request.user.first_name,
        "login_links": request.user.login_links,
        "user_has_no_login_links": user_has_no_login_links,
        "request": request,
        "logout_url": "/logout"
    }

    return templates.TemplateResponse("home.html", page_content)

@app.get("/favicon.ico", include_in_schema=False)
def get_favicon():
    return FileResponse("assets/favicon.ico")

@app.get("/logout", dependencies=[
        Security(check_user_login, scopes=[])
    ])
async def logout(request: Request):
    service_container = request.app.state.service_container
    cognito_service = service_container.cognito_service()

    app_base_url = f"{request.url.scheme}://{request.url.netloc}"
    redirect_url = f"{app_base_url}/"

    cognito_logout_url = cognito_service.get_logout_endpoint(
        redirect_url
    )

    request.session.clear()
    regenerate_session_id(request)

    raise HTTPException(
        status_code=status.HTTP_307_TEMPORARY_REDIRECT,
        headers={'Location': cognito_logout_url}
    )

    
if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000)