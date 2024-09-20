import os
import pandas as pd
import pefile
from pyspark.sql import SparkSession
from pyspark.sql import DataFrame
from sqlalchemy import create_engine


spark = SparkSession.builder \
    .appName("Data Processing") \
    .getOrCreate()

def download_from_s3(s3_url: str) -> DataFrame:
    """Download data from S3 and return as a DataFrame."""
    df = spark.read.csv(s3_url, header=True, inferSchema=True)
    return df


def get_file_metadata(file_path: str) -> dict:
    """Extract metadata from PE files."""
    try:
        pe = pefile.PE(file_path)
        file_metadata = {
            "file_path": file_path,
            "file_size": os.path.getsize(file_path),
            "file_type": os.path.splitext(file_path)[1],  # Extract file extension
            "architecture": "x64" if 'PE32+' in pe.FILE_HEADER.Characteristics else "x32",
            "number_of_imports": len(pe.imports),
            "number_of_exports": len(pe.exports) if hasattr(pe, 'exports') else 0,
        }
        return file_metadata
    except Exception as e:
        print(f"Error processing {file_path}: {e}")
        return None


def preprocess_data(df: DataFrame) -> DataFrame:
    """Process DataFrame and extract metadata for each file."""
    metadata_list = []

    for row in df.collect():  # Collect the DataFrame to the driver
        file_path = row['file_path']  # Adjust according to your DataFrame schema
        metadata = get_file_metadata(file_path)
        if metadata:
            metadata_list.append(metadata)

    # Convert metadata list to DataFrame
    metadata_df = pd.DataFrame(metadata_list)
    return spark.createDataFrame(metadata_df)


def upload_metadata_to_db(metadata_df: DataFrame, db_url, table_name):
    engine = create_engine(db_url)
    metadata_df.toPandas().to_sql(table_name, engine, if_exists='append', index=False)


if __name__ == "__main__":
    # URL to your S3 data (make sure it is accessible)
    s3_url = 's3://your-bucket-name/path/to/your/data.csv'

    # Download and preprocess data
    raw_df = download_from_s3(s3_url)
    processed_df = preprocess_data(raw_df)

    # Define your PostgreSQL connection details
    db_url = os.getenv('DATABASE_URL')
    upload_metadata_to_db(processed_df, db_url, 'metadata_table')

    spark.stop()