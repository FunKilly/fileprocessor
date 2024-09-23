from src.database.db import get_db_session
from src.database.file_metadata import FileMetadata
from src.file_processing.services import (
    get_metadeta_from_files,
    get_udf,
    logger,
    process_file,
)
from src.file_storage.storage import FileSourceEnum, get_files_to_process
from src.utils import EnvironmentEnum, initialize_spark_session


def process_files(
    number_of_files: int = 1,
    file_source: FileSourceEnum = FileSourceEnum.S3,
    environment: EnvironmentEnum = EnvironmentEnum.LOCAL,
):
    logger.info(
        f"{number_of_files} files to process. File source: {file_source.value}. Environment: {environment.value}"
    )
    spark_session = initialize_spark_session(
        environment=environment, file_source=file_source
    )

    db_session = get_db_session()
    existing_file_paths = FileMetadata.get_all_file_paths(db_session)

    files_df = get_files_to_process(
        file_source, spark_session, number_of_files, existing_file_paths
    )

    udf_function = get_udf(process_file)
    metadeta_df = get_metadeta_from_files(files_df, udf_function)
    postgres_url = "jdbc:postgresql://localhost:5432/processing_db"
    table_name = "file_metadata"

    properties = {
        "user": "user",
        "password": "Test1234!",
        "driver": "org.postgresql.Driver",
    }

    metadeta_df.write.jdbc(
        url=postgres_url, table=table_name, mode="append", properties=properties
    )


if __name__ == "__main__":
    import os
    import time

    os.environ["DATABASE_URL"] = (
        "postgresql+psycopg2://user:Test1234!@localhost:5432/processing_db"
    )
    start_time = time.time()
    process_files(number_of_files=10, environment=EnvironmentEnum.LOCAL)
    end_time = time.time()

    print(f"took {end_time - start_time}")
