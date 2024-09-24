import pytest
from pyspark.sql import SparkSession

from src.file_storage.s3 import S3Storage


@pytest.fixture(autouse=True)
def mock_get_session(session, mocker):
    mocker.patch("src.file_storage.s3.get_db_session", return_value=session)


@pytest.fixture
def spark_session(mocker):
    # Create a Spark session
    spark = SparkSession.builder.master("local[*]").getOrCreate()
    mocker.patch("src.utils.utils.get_spark_session", return_value=spark)
    mocker.patch("pyspark.context.SparkContext.addPyFile")
    yield spark
    spark.stop()


def test_list_files(spark_session, mocker, mock_get_session):
    storage = S3Storage(file_amount=10)

    downloaded_df_1 = spark_session.createDataFrame(
        [("file1.txt",), ("file2.txt",)], ["path"]
    )

    downloaded_df_2 = spark_session.createDataFrame(
        [("existing_file_1",), ("file3.txt",)], ["path"]
    )

    storage.download_files = mocker.Mock(side_effect=[downloaded_df_1, downloaded_df_2])

    result_df = storage.list_files()

    assert result_df.collect() == (downloaded_df_1.union(downloaded_df_2)).collect()


def test_filter_files(spark_session, mocker):
    storage = S3Storage(file_amount=10)

    files_df = spark_session.createDataFrame(
        [("file1.txt",), ("file2.txt",), ("existing_file_1",)], ["path"]
    )

    existing_file_paths = spark_session.sparkContext.broadcast(
        ["existing_file_1", "existing_file_2"]
    )

    result_df = storage.filter_files(
        files=files_df, existing_file_paths=existing_file_paths
    )

    expected_filtered_df = spark_session.createDataFrame(
        [("file1.txt",), ("file2.txt",)], ["path"]
    )

    assert result_df.collect() == expected_filtered_df.collect()
