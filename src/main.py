from src.file_processing.utils import initialize_spark_session
from src.file_processing.services import get_metadeta_from_files, get_udf, process_file

from src.database.db import get_db_session

from src.database.file_metadata import FileMetadata
from src.utils import EnvironmentEnum
from src.file_storage.storage import get_files_to_process, FileSourceEnum


def process_files(
    number_of_files: int = 1,
    file_source: FileSourceEnum = FileSourceEnum.S3,
    environment: EnvironmentEnum = EnvironmentEnum.LOCAL,
):
    spark_session = initialize_spark_session(
        environment=environment, file_source=file_source
    )
    # db_session = get_db_session()
    # existing_file_paths = FileMetadata.get_all_file_paths(db_session)
    existing_file_paths = []

    files_df = get_files_to_process(
        file_source, spark_session, number_of_files, existing_file_paths
    )

    udf_function = get_udf(process_file)
    metadeta_df = get_metadeta_from_files(files_df, udf_function)
    print(metadeta_df.count())
    metadeta_df.show()


if __name__ == "__main__":
    import time

    start_time = time.time()
    process_files(number_of_files=100)
    end_time = time.time()

    print(f"took {end_time - start_time}")
