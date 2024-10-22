from typing import Union
from fastapi.requests import HTTPConnection, Request


def generate_app_base_url(
    request: Union[Request, HTTPConnection],
    app_env: str,
) -> str:
    """
    This function contains utility functions for working with
    URLs based on the environment.
    """
    return f"https://{request.url.netloc}" \
        if app_env == 'aws' else f"{request.url.scheme}://{request.url.netloc}"
