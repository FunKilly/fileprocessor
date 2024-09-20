from pyspark.sql import SparkSession

# Initialize Spark session
spark = SparkSession.builder \
    .appName("Distributed S3 File Downloader") \
    .master("local[*]") \
    .config("spark.hadoop.fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem") \
    .config("spark.hadoop.fs.s3a.endpoint", "s3.eu-central-1.amazonaws.com") \
    .config("spark.hadoop.fs.s3a.path.style.access", "true") \
    .config("spark.jars.packages", "org.apache.hadoop:hadoop-aws:3.2.0,org.apache.hadoop:hadoop-common:3.2.0") \
    .config('spark.hadoop.fs.s3a.aws.credentials.provider', 'org.apache.hadoop.fs.s3a.SimpleAWSCredentialsProvider') \
    .config("spark.executor.memory", "4g") \
    .config("spark.driver.memory", "4g") \
    .config("spark.default.parallelism", "100") \
    .getOrCreate()

# Use the S3 path
s3_path = "s3a://s3-nord-challenge-data/0/"

# List the files from the S3 bucket
files_df = spark.read.format("binaryFile").load(s3_path)
file_paths = files_df.select("path").rdd.flatMap(lambda x: x).collect()


import os
import pefile
from pyspark.sql.functions import udf

from pyspark.sql import SparkSession

from pyspark.sql.types import StructType, StructField, StringType, LongType, IntegerType
import pefile
import tempfile

# Initialize Spark session
spark = SparkSession.builder \
    .appName("S3 PE File Processor") \
    .config("spark.hadoop.fs.s3a.impl", "org.apache.hadoop.fs.s3a.S3AFileSystem") \
    .config("spark.hadoop.fs.s3a.endpoint", "s3.eu-central-1.amazonaws.com") \
    .config("spark.hadoop.fs.s3a.path.style.access", "true") \
    .getOrCreate()

# Define the S3 path
s3_path = "s3a://s3-nord-challenge-data/0/*"

# Load files from S3 as binary
files_df = spark.read.format("binaryFile").load(s3_path)

# Define a function to process the PE files
def process_file(file_path, file_content):
    try:
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(file_content)
            temp_file.flush()
            print('processing file')
            # Load the PE file from the temporary file path
            pe = pefile.PE(temp_file.name)

            # Extract metadata
            architecture = "x64" if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else "x86"
            size = temp_file.tell()  # Get the size of the temporary file
            number_of_imports = len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0
            number_of_exports = len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0

        return file_path, architecture, size, number_of_imports, number_of_exports

    except Exception as e:
        print(f"Error processing file: {str(e)}")
        return None, None, None, 0, 0

# Register the UDF to distribute processing across workers
process_udf = udf(process_file, StructType([
    StructField("file_path", StringType(), True),
    StructField("architecture", StringType(), True),
    StructField("size", LongType(), True),
    StructField("number_of_imports", IntegerType(), True),
    StructField("number_of_exports", IntegerType(), True)
]))

# Apply the UDF to the files DataFrame
files_with_metadata_df = files_df.withColumn("metadata", process_udf(files_df["path"], files_df["content"]))

# Explode the metadata columns into separate fields
files_with_metadata_df = files_with_metadata_df.select(
    "path",
    "metadata.file_path",
    "metadata.architecture",
    "metadata.size",
    "metadata.number_of_imports",
    "metadata.number_of_exports"
)

# Show the results
files_with_metadata_df.show()
