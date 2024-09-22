from pyspark.sql.functions import udf, monotonically_increasing_id
from pyspark.sql.types import StructType, StructField, StringType, LongType, IntegerType

from .entities import PeFile
import io
import pefile
from logging import getLogger

logger = getLogger(__name__)


def process_file(file_path, file_content):
    logger.info(f"Processing {file_path}")
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
