FROM python:3.10-alpine

RUN apk update && apk add --no-cache \
    postgresql-dev \
    postgresql-client \
    gcc \
    musl-dev \
    python3-dev \
    libffi-dev \
    openssl-dev \
    && pip install --upgrade pip

COPY ./requirements.txt .

RUN python3 -m pip install -r requirements.txt