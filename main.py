import toml
import uvicorn
from dotenv import load_dotenv
import fastapi
from starlette.responses import FileResponse

load_dotenv()

API_VERSION = toml.load("pyproject.toml")["tool"]["poetry"]["version"]
API_DESCRIPTION = toml.load("pyproject.toml")["tool"]["poetry"]["description"]

app = fastapi.FastAPI(
    title="PostNL - Federated Engineers login portal",
    descripton=API_DESCRIPTION,
    version=API_VERSION
)


@app.get("/")
def home():
    return "Welcome to the portal!"


@app.get("/favicon.ico", include_in_schema=False)
def get_favicon():
    return FileResponse("assets/favicon.ico")


if __name__ == '__main__':
    uvicorn.run(app, host="0.0.0.0", port=8000)
