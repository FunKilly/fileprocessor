import time
from logging import getLogger

from src.database.models import FileMetadata
from src.database.services import add_metadata_to_database
from src.database.utils import get_db_session
from src.file_processing.services import get_metadata_df
from src.file_storage.storage import FileSourceEnum
from src.utils.settings import settings
from src.utils.utils import EnvironmentEnum, initialize_spark_session

logger = getLogger(__name__)


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
    metadeta_df = get_metadata_df(
        existing_file_paths, file_source, number_of_files, spark_session
    )
    add_metadata_to_database(metadeta_df)


if __name__ == "__main__":

    start_time = time.time()
    environment = (
        EnvironmentEnum.LIVE
        if settings.ENVIRONMENT == "live"
        else EnvironmentEnum.LOCAL
    )
    process_files(number_of_files=100, environment=environment)
    end_time = time.time()

    print(f"took {end_time - start_time}")
