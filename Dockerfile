FROM python:3.11-slim AS base-stage

ENV VENV_PATH="/app/.venv"

WORKDIR /app

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y && apt-get upgrade -y

FROM base-stage AS builder

RUN apt-get install -y git && pip install poetry

COPY ./pyproject.toml ./poetry.lock /app/

RUN POETRY_VIRTUALENVS_IN_PROJECT=true POETRY_NO_INTERACTION=1 poetry install

FROM base-stage AS final

COPY --from=builder $VENV_PATH $VENV_PATH

COPY . /app

ENV PATH="$VENV_PATH/bin:$PATH"

RUN . $VENV_PATH/bin/activate

EXPOSE 80

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
