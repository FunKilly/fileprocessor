from pyspark.sql import SparkSession
from pyspark.sql.functions import udf, monotonically_increasing_id
from pyspark.sql.types import StructType, StructField, StringType, LongType, IntegerType
import pefile
import io
import logging
from enum import StrEnum
from dataclasses import dataclass, field


def initialize_spark_session():
    return (
        SparkSession.builder.appName("Distributed S3 File Downloader")
        .master("local[*]")
        .config("spark.default.parallelism", "32")
        .config("spark.hadoop.fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem")
        .config("spark.hadoop.fs.s3a.endpoint", "s3.eu-central-1.amazonaws.com")
        .config("spark.hadoop.fs.s3a.path.style.access", "true")
        .config(
            "spark.jars.packages",
            "org.apache.hadoop:hadoop-aws:3.2.0,org.apache.hadoop:hadoop-common:3.2.0",
        )
        .config(
            "spark.hadoop.fs.s3a.aws.credentials.provider",
            "org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider",
        )
        .getOrCreate()
    )


def list_files_from_s3(session):
    s3_path = "s3a://s3-nord-challenge-data/0/"
    return session.read.format("binaryFile").load(s3_path)


class FileSourceEnum(StrEnum):
    S3 = "S3"


def get_files_to_process(file_source, session):
    if file_source == FileSourceEnum.S3:
        return list_files_from_s3(session)


@dataclass
class PeFile:
    """Class for keeping track of an item in inventory."""

    content: io.BytesIO
    path: str
    pe_handler: pefile.PE = field(init=False)
    architecture: str = field(init=False)
    imports_number: int = field(init=False)
    exports_number: int = field(init=False)
    size: int = field(init=False)

    def __post_init__(self):
        self.pe_handler = pefile.PE(data=self.content.read())
        self.architecture = self._get_architecture_type()
        self.imports_number = self._get_imports_number()
        self.exports_number = self._get_exports_number()
        self.size = self._get_size()

    def _get_architecture_type(self) -> str | None:
        if not hasattr(self.pe_handler, "FILE_HEADER") or not hasattr(
            self.pe_handler.FILE_HEADER, "Machine"
        ):
            return None

        machine_type = self.pe_handler.FILE_HEADER.Machine
        # Determine the architecture based on the Machine field
        if machine_type == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            return "x64"
        elif machine_type == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            return "x32"
        else:
            return None

    def _get_imports_number(self) -> int:
        return (
            len(self.pe_handler.DIRECTORY_ENTRY_IMPORT)
            if hasattr(self.pe_handler, "DIRECTORY_ENTRY_IMPORT")
            else 0
        )

    def _get_exports_number(self) -> int:
        return (
            len(self.pe_handler.DIRECTORY_ENTRY_EXPORT.symbols)
            if hasattr(self.pe_handler, "DIRECTORY_ENTRY_EXPORT")
            else 0
        )

    def _get_size(self) -> int:
        return self.content.getbuffer().nbytes

    def get_metadata(self):
        return (
            self.path,
            self.architecture,
            self.size,
            self.imports_number,
            self.exports_number,
        )


def process_file(file_path, file_content):
    logging.info(f"Processing {file_path}")
    try:
        pe_file = PeFile(content=io.BytesIO(file_content), path=file_path)
        return pe_file.get_metadata()

    except pefile.PEFormatError as e:
        print(f"Error processing file: {str(e)}")
        return file_path, None, 0, 0, 0


def get_udf(udf_function):
    return udf(
        udf_function,
        StructType(
            [
                StructField("file_path", StringType(), True),
                StructField("architecture", StringType(), True),
                StructField("size", LongType(), True),
                StructField("number_of_imports", IntegerType(), True),
                StructField("number_of_exports", IntegerType(), True),
            ]
        ),
    )


def get_metadeta_from_files(files_df, udf_function):
    files_with_metadata_df = files_df.withColumn(
        "metadata", udf_function(files_df["path"], files_df["content"])
    )

    # Explode the metadata columns into separate fields
    return files_with_metadata_df.select(
        "path",
        "metadata.file_path",
        "metadata.architecture",
        "metadata.size",
        "metadata.number_of_imports",
        "metadata.number_of_exports",
    )


def process_files(file_source: FileSourceEnum = FileSourceEnum.S3):
    spark_session = initialize_spark_session()
    files_df = get_files_to_process(file_source, spark_session)

    udf_function = get_udf(process_file)
    metadeta_df = get_metadeta_from_files(files_df, udf_function)

    metadeta_df.show(n=20)


if __name__ == "__main__":
    import time

    start_time = time.time()
    process_files(FileSourceEnum.S3)
    end_time = time.time()
    print(f"Took {end_time - start_time}")
