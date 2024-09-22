from enum import StrEnum
from .s3 import list_files_from_s3


class FileSourceEnum(StrEnum):
    S3 = "S3"


def get_files_to_process(
    file_source, session, number_of_files: int, excluded_paths: list[str]
):
    if file_source == FileSourceEnum.S3:
        return list_files_from_s3(session, number_of_files, excluded_paths)

    raise Exception("Invalid file source")
