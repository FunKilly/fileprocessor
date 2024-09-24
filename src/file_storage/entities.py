from enum import StrEnum

from src.file_storage.base import Storage


class FileSourceEnum(StrEnum):
    S3 = "S3"


def get_file_source_to_handler_map(file_source: FileSourceEnum) -> Storage:
    from .s3 import S3Storage  # Lazy import inside function to avoid circular import

    return {FileSourceEnum.S3: S3Storage}.get(file_source, FileSourceEnum.S3)
