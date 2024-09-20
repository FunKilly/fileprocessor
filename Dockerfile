FROM python:3.12-slim-bullseye

WORKDIR /app

# Install required packages
COPY pyproject.toml poetry.lock ./
RUN pip install poetry && poetry install

# Install PySpark and SQLAlchemy dependencies
RUN pip install pyspark sqlalchemy

# Copy the application code
COPY . .

CMD ["python", "main.py"]
