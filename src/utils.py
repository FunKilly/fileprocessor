from enum import StrEnum
from multiprocessing import cpu_count

from pyspark.sql import SparkSession

from src.file_storage.storage import FileSourceEnum

parallelism = min(32, cpu_count())

from logging import getLogger

logger = getLogger(__name__)


class EnvironmentEnum(StrEnum):
    LOCAL = "local"
    LIVE = "live"


def initialize_spark_session(
    environment: EnvironmentEnum, file_source: FileSourceEnum
) -> SparkSession:
    master_url = (
        "local[*]" if environment == EnvironmentEnum.LOCAL else "spark://localhost:7077"
    )
    builder = (
        SparkSession.builder.appName("Distributed File Downloader")
        .master(master_url)
        .config("spark.default.parallelism", parallelism)
        .config("spark.executor.extraClassPath", "src/jars/postgresql-42.3.4.jar")
        .config("spark.driver.extraClassPath", "src/jars/postgresql-42.3.4.jar")
        .config("spark.executor.extraJavaOptions", "-XX:+UseG1GC")
    )

    if file_source == FileSourceEnum.S3:
        builder.config(
            "spark.hadoop.fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem"
        ).config("spark.hadoop.fs.s3a.path.style.access", "true").config(
            "spark.jars.packages",
            "org.apache.hadoop:hadoop-aws:3.2.0,org.apache.hadoop:hadoop-common:3.2.0",
        ).config(
            "spark.hadoop.fs.s3a.aws.credentials.provider",
            "org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider",
        )

    if environment == EnvironmentEnum.LOCAL:
        builder = builder.config("spark.driver.memory", "8g")
        builder = builder.config("spark.executor.memory", "8g")
        builder = builder.config("spark.executor.cores", "8")

    session = builder.getOrCreate()

    session.sparkContext.addPyFile("src.zip")
    session.sparkContext.setLogLevel("WARNING")

    logger.warning(f"Running application with {parallelism}")
    return session
