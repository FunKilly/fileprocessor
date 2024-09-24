FROM bitnami/spark:latest

RUN pip install pefile

USER root
RUN apt-get update && apt-get install -y \
    libsnappy-dev \
    liblz4-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the user back to the default
USER 1001

# Set up environment (if needed)
ENV SPARK_RPC_AUTHENTICATION_ENABLED=no
ENV SPARK_RPC_ENCRYPTION_ENABLED=no
ENV SPARK_LOCAL_STORAGE_ENCRYPTION_ENABLED=no
ENV SPARK_SSL_ENABLED=no