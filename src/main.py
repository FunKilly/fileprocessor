import argparse
import time
from logging import getLogger

from src.database.services import add_metadata_to_database
from src.file_processing.services import extract_metadata_from_files
from src.file_storage.entities import FileSourceEnum, get_file_source_to_handler_map
from src.utils.settings import settings

logger = getLogger(__name__)


def process_files(
    number_of_files: int = 1,
    file_source: FileSourceEnum = FileSourceEnum.S3,
) -> None:
    storage_handler = get_file_source_to_handler_map(file_source)(
        file_amount=number_of_files
    )
    files_df = storage_handler.list_files()

    metadeta_df = extract_metadata_from_files(files_df)
    add_metadata_to_database(metadeta_df)


def get_script_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Process a specified number of files.")
    parser.add_argument(
        "-n", "--number", type=int, default=100, help="Number of files to process"
    )

    return parser.parse_args()


if __name__ == "__main__":
    args = get_script_arguments()

    logger.info(
        f"{args.number} files to process. File source: {settings.FILE_SOURCE.value}. "
        f"Environment: {settings.ENVIRONMENT.value}"
    )

    logger.error(f" LOGGING {args.number}")

    start_time = time.time()
    process_files(number_of_files=args.number)
    end_time = time.time()

    print(f"took {end_time - start_time}")
