from multiprocessing import cpu_count

from pyspark.sql import SparkSession

from src.file_storage.entities import FileSourceEnum
from src.utils.settings import settings

from .entities import EnvironmentEnum


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
        .config("spark.default.parallelism", cpu_count())
        .config("spark.jars", "/opt/postgresql-42.5.0.jar")
        .config("spark.eventLog.enabled", "false")
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
        ).config("spark.hadoop.fs.s3a.connection.maximum", "75").config(
            "spark.hadoop.fs.s3a.threads.max", "50")

    if environment == EnvironmentEnum.LOCAL:
        builder.config("spark.jars", "jars/postgresql-42.5.0.jar")

    session = builder.getOrCreate()

    session.sparkContext.addPyFile("src.zip")

    return session


def singleton_function(func):
    instance = None

    def wrapper(*args, **kwargs):
        nonlocal instance
        if instance is None:
            instance = func(*args, **kwargs)
        return instance

    return wrapper


@singleton_function
def get_spark_session() -> SparkSession:
    return initialize_spark_session(settings.ENVIRONMENT, settings.FILE_SOURCE)
