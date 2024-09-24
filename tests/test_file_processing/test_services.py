import pefile
import pytest
from pyspark.sql import SparkSession

from src.file_processing.services import (
    CORRUPTED_FILE,
    extract_metadata_from_files,
    get_udf,
    process_file,
)


# Set up a Spark session for testing
@pytest.fixture(scope="module")
def spark():
    spark_session = SparkSession.builder.master("local").appName("Test").getOrCreate()
    yield spark_session
    spark_session.stop()


# Test for process_file
def test_process_file_valid(mocker):
    file_path = "valid_file.exe"
    valid_content = b"valid content"

    mock_pe_file = mocker.patch("src.file_processing.services.PeFile")
    mock_instance = mock_pe_file.return_value
    mock_instance.get_metadata.return_value = (
        "valid_file.exe",
        "exe",
        "x86_64",
        12345,
        5,
        10,
    )

    result = process_file(file_path, valid_content)

    assert result == ("valid_file.exe", "exe", "x86_64", 12345, 5, 10)


def test_process_file_corrupted(mocker):
    file_path = "corrupted_file.exe"
    invalid_content = b"corrupted content"  # Not a valid PE file

    mocker.patch(
        "src.file_processing.services.PeFile",
        side_effect=pefile.PEFormatError("Invalid PE format"),
    )

    result = process_file(file_path, invalid_content)

    assert result == (file_path, *CORRUPTED_FILE)


def test_get_udf():
    sample_udf = lambda file_path, file_content: (
        file_path,
        "exe",
        "x86_64",
        12345,
        5,
        10,
    )
    udf_function = get_udf(sample_udf)

    assert udf_function.returnType.fields[0].name == "file_path"
    assert len(udf_function.returnType.fields) == 6  # Ensure we have 6 output fields


def test_extract_metadata_from_files(spark, mocker):
    data = [("valid_file.exe", b"valid content")]
    schema = ["path", "content"]
    files_df = spark.createDataFrame(data, schema)

    result_df = extract_metadata_from_files(files_df)

    assert result_df.count() == 1
    assert result_df.collect()[0]["file_path"] == "valid_file.exe"
