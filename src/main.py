import pyspark
from pyspark.sql import SparkSession
from sqlalchemy import create_engine
import os
import pefile

# Initialize Spark session
spark = SparkSession.builder \
    .master("spark://spark-master:7077") \
    .appName("FileProcessing") \
    .getOrCreate()

# Initialize Database connection with SQLAlchemy
DATABASE_URL = os.getenv('DATABASE_URL')
engine = create_engine(DATABASE_URL)


def download_and_process_files(s3_url, catalog_name):
    # Logic to download files from S3, here you'd utilize boto3 or PySpark’s S3 support

    # Simulate file list for processing
    file_list = ['/path/to/file1.exe', '/path/to/file2.dll']

    # Define a schema for the metadata
    metadata_schema = ["file_path", "size", "file_type", "architecture", "imports", "exports"]

    # PySpark UDF to extract metadata from a file
    def extract_metadata(file_path):
        # Implement metadata extraction logic here
        try:
            pe = pefile.PE(file_path)
        except pefile.PEFormatError:
            return {
            "file_path": file_path,
            "size": os.path.getsize(file_path),
            "file_type": "exe" if file_path.endswith(".exe") else "dll",
            "architecture": None,
            "imports":  0,
            "exports":  0
        }

        return {
            "file_path": file_path,
            "size": os.path.getsize(file_path),
            "file_type": "exe" if file_path.endswith(".exe") else "dll",
            "architecture": "x64" if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else "x86",
            "imports": len(pe.DIRECTORY_ENTRY_IMPORT) if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
            "exports": len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
        }

    # Convert file list to RDD
    file_rdd = spark.sparkContext.parallelize(file_list)

    # Apply the metadata extraction function on each file
    metadata_rdd = file_rdd.map(extract_metadata)

    # Convert the result to a DataFrame
    metadata_df = spark.createDataFrame(metadata_rdd, schema=metadata_schema)

    # Write metadata to database using SQLAlchemy
    metadata_df.write.jdbc(url=DATABASE_URL, table='file_metadata', mode='append')


# Download and process the files from S3
download_and_process_files(s3_url="s3://your-bucket/catalog/", catalog_name="catalog-name")
