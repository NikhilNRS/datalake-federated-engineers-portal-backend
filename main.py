import uvicorn
from fastapi import FastAPI, Request, HTTPException, status
from starlette.responses import RedirectResponse
from starsessions import SessionMiddleware, regenerate_session_id
from dotenv import load_dotenv
import os
import logging

# Load environment variables from .env file
load_dotenv()

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="PostNL - Federated Engineers login portal",
    version="0.1.0",
    docs_url="/docs",  # Enable docs for debugging
    redoc_url=None,
    openapi_url="/openapi.json"
)

# Add SessionMiddleware
app.add_middleware(
    SessionMiddleware,
    store='redis://:dev@cache:6379/0',  # Use the correct store parameter for Redis
    cookie_name="session",
    lifetime=3600,
)

@app.get("/logout", include_in_schema=True)
async def logout(request: Request):
    logger.info("Logout endpoint reached.")
    
    # Load the session
    await request.session.load()
    
    session = request.session

    if not session.get("user"):
        logger.warning("User not logged in.")
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not logged in")

    # Clear the server-side session
    logger.info("Clearing session.")
    session.clear()

    # Regenerate the session ID
    logger.info("Regenerating session ID.")
    await regenerate_session_id(request)

    # Logout from Cognito
    cognito_logout_url = (
        f"https://{os.getenv('COGNITO_USER_POOL_DOMAIN')}.auth.{os.getenv('AWS_REGION')}.amazoncognito.com/logout?"
        f"client_id={os.getenv('COGNITO_CLIENT_ID')}&"
        f"logout_uri={os.getenv('LOGOUT_REDIRECT_URI')}"
    )
    logger.info(f"Redirecting to {cognito_logout_url}")
    return RedirectResponse(url=cognito_logout_url)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
