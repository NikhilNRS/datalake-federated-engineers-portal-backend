FROM python:3.11-slim AS requirements-stage

WORKDIR /tmp

RUN pip install poetry

COPY ./pyproject.toml ./poetry.lock /tmp/

RUN poetry export -f requirements.txt --output requirements.txt --without-hashes

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update -y && apt-get upgrade -y && DEBIAN_FRONTEND=noninteractive apt-get install -y apt-utils && apt-get install -y git

COPY --from=requirements-stage /tmp/requirements.txt /app/requirements.txt

RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt && rm -rf /root/.cache/pip/* && apt-get remove -y git

COPY . /app

EXPOSE 80

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "80"]
