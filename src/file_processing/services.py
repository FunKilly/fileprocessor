import io
from logging import getLogger

import pefile
from pyspark.sql.functions import udf
from pyspark.sql.types import IntegerType, LongType, StringType, StructField, StructType

from .entities import PeFile

logger = getLogger(__name__)
CORRUPTED_FILE = (None, None, 0, 0, 0)


def process_file(file_path, file_content):
    try:
        pe_file = PeFile(content=io.BytesIO(file_content), path=file_path)
        return pe_file.get_metadata()
    except pefile.PEFormatError as e:
        logger.error(f"Error processing file: {str(e)}")
        return file_path, *CORRUPTED_FILE


def get_udf(udf_function):
    return udf(
        udf_function,
        StructType(
            [
                StructField("file_path", StringType(), True),
                StructField("file_type", StringType(), True),
                StructField("architecture", StringType(), True),
                StructField("size", LongType(), True),
                StructField("imports", IntegerType(), True),
                StructField("exports", IntegerType(), True),
            ]
        ),
    )


def extract_metadata_from_files(files_df):
    files_df.cache()
    udf_function = get_udf(process_file)

    metadeta_df = files_df.withColumn(
        "metadata", udf_function(files_df["path"], files_df["content"])
    ).select(
        "metadata.file_path",
        "metadata.file_type",
        "metadata.architecture",
        "metadata.size",
        "metadata.imports",
        "metadata.exports",
    )

    return metadeta_df
