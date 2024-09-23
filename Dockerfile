FROM apache/spark:3.5.2 AS base

USER root

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on \
    PIP_DEFAULT_TIMEOUT=100 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1 \
    PYSETUP_PATH="/opt/pysetup" \
    VENV_PATH="/opt/pysetup/.venv"

ENV PATH="$POETRY_HOME/bin:$VENV_PATH/bin:$PATH"

RUN apt-get update && \
    apt-get install --no-install-recommends -y \
        build-essential \
        libpq-dev \
        zip \
        software-properties-common && \
    add-apt-repository ppa:deadsnakes/ppa && \
    apt-get update && \
    apt-get install --no-install-recommends -y \
        python3.12 \
        python3.12-venv \
        python3.12-dev \
        python3-pip && \
    update-alternatives --install /usr/bin/python python /usr/bin/python3.12 1 && \
    update-alternatives --install /usr/bin/pip pip /usr/bin/pip3 1 && \
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.12 1 && \
    curl -sSL https://install.python-poetry.org | python3 - && \
    mkdir -p $PYSETUP_PATH && \
    chmod +x $PYSETUP_PATH

# Dependencies
FROM base AS builder

WORKDIR $PYSETUP_PATH
COPY ./poetry.lock ./pyproject.toml ./
RUN poetry install --without dev --no-root

COPY ./src /src
RUN zip -r src.zip /src

# Final production image
FROM base AS production

COPY --from=builder $VENV_PATH $VENV_PATH
COPY --from=builder $PYSETUP_PATH/src.zip /processing-app/src.zip
COPY entrypoint.sh entrypoint.sh

COPY . /processing-app/
COPY alembic.ini ./processing-app/
WORKDIR /processing-app

# Add the PostgreSQL JDBC driver
RUN curl -L -o /opt/postgresql-42.5.0.jar https://jdbc.postgresql.org/download/postgresql-42.5.0.jar


RUN /usr/bin/python3.12 --version

ENTRYPOINT ["bash", "/processing-app/entrypoint.sh", "10"]
