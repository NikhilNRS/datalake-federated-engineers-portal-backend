# Federated Engineers Portal Backend

This codebase contains the code for the login portal for federated engineers that work on PostNL's 
DataLake. It uses OneWelcome (through AWS Cognito) for authentication.

## Prerequisites

- Python 3.11 or above
- Poetry package manager

## Setup

Install dependencies:

```shell
poetry install
```

Configure application:

```shell
cp .env.dist .env
```

## Usage

Run API in development mode:

```shell
uvicorn main:app --reload
```
