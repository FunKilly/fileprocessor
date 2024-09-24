from enum import StrEnum

from pyspark.sql import SparkSession

from src.file_storage.storage import FileSourceEnum
from src.utils.settings import settings


class EnvironmentEnum(StrEnum):
    LOCAL = "local"
    LIVE = "live"


def initialize_spark_session(
    environment: EnvironmentEnum, file_source: FileSourceEnum
) -> SparkSession:
    master_url = (
        "local[*]"
        if environment == EnvironmentEnum.LOCAL
        else "spark://spark-master:7077"
    )

    builder = (
        SparkSession.builder.appName("Distributed File Downloader")
        .master(master_url)
        .config("spark.executor.memory", settings.SPARK_WORKER_MEMORY)
        .config("spark.executor.cores", settings.SPARK_WORKER_CORES)
        .config("spark.jars", "/opt/postgresql-42.5.0.jar")
    )

    if file_source == FileSourceEnum.S3:
        builder.config(
            "spark.hadoop.fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem"
        ).config("spark.hadoop.fs.s3a.path.style.access", "true").config(
            "spark.jars.packages",
            "org.apache.hadoop:hadoop-aws:3.2.0,org.apache.hadoop:hadoop-common:3.2.0",
        ).config(
            "spark.hadoop.fs.s3a.aws.credentials.provider",
            "org.apache.hadoop.fs.s3a.AnonymousAWSCredentialsProvider",
        ).config(
            "spark.hadoop.fs.s3a.connection.maximum", "100"
        ).config(
            "spark.hadoop.fs.s3a.threads.max", "100"
        )

    if environment == EnvironmentEnum.LOCAL:
        builder.config("spark.driver.memory", "8g").config(
            "spark.executor.memory", "8g"
        ).config("spark.executor.cores", "8").config(
            "spark.jars", "jars/postgresql-42.5.0.jar"
        ).config(
            "spark.executor.memory", "4G"
        ).config(
            "spark.executor.cores", 4
        )

    session = builder.getOrCreate()

    session.sparkContext.addPyFile("src.zip")
    session.sparkContext.setLogLevel("WARN")

    return session
