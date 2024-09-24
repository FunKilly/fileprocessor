import argparse
import time
from logging import getLogger

from src.database.services import add_metadata_to_database
from src.file_processing.services import extract_metadata_from_files
from src.file_storage.entities import FileSourceEnum, get_file_source_to_handler_map
from src.utils.settings import settings
from src.utils.utils import EnvironmentEnum

logger = getLogger(__name__)


def process_files(
    number_of_files: int = 1,
    file_source: FileSourceEnum = FileSourceEnum.S3,
    environment: EnvironmentEnum = EnvironmentEnum.LOCAL,
):
    logger.info(
        f"{number_of_files} files to process. File source: {file_source.value}. "
        f"Environment: {environment.value}"
    )

    StorageHandlerClass = get_file_source_to_handler_map(file_source)
    storage_handler = StorageHandlerClass(file_amount=number_of_files)
    files_df = storage_handler.list_files()

    metadeta_df = extract_metadata_from_files(files_df)
    add_metadata_to_database(metadeta_df)


def get_script_arguments():
    parser = argparse.ArgumentParser(description="Process a specified number of files.")
    parser.add_argument(
        "-n", "--number", type=int, default=100, help="Number of files to process"
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = get_script_arguments()

    start_time = time.time()
    environment = (
        EnvironmentEnum.LIVE
        if settings.ENVIRONMENT == "live"
        else EnvironmentEnum.LOCAL
    )

    logger.error(f" LOGGING {args.number}")
    process_files(number_of_files=args.number, environment=environment)
    end_time = time.time()

    print(f"took {end_time - start_time}")
