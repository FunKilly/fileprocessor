from multiprocessing import cpu_count

from pyspark.sql import DataFrame

from src.database.models import FileMetadata
from src.database.utils import get_db_session
from src.utils.settings import settings
from src.utils.utils import get_spark_session

from .base import Storage


class S3Storage(Storage):
    def __init__(self, file_amount):
        self.session = get_spark_session()
        self.file_amount = file_amount

    def download_files(self, path: str) -> DataFrame:
        files = self.session.read.format("binaryFile").load(path)

        # Reduce number of partitions for better performance while working on small files
        files = files.coalesce(cpu_count())
        return files

    def list_files(self) -> DataFrame:
        dataframes = []
        db_session = get_db_session()

        existing_file_paths = FileMetadata.get_all_file_paths(db_session)
        broadcast_paths = self.session.sparkContext.broadcast(existing_file_paths)

        for directory in settings.s3_storage.DIRECTORIES:
            s3_path = f"s3a://{settings.s3_storage.BUCKET_NAME}/{directory}/"

            files = self.download_files(s3_path)
            filtered_files = self.filter_files(files, broadcast_paths)
            dataframes.append(filtered_files)

        combined_df = dataframes[0]
        for df in dataframes[1:]:
            combined_df = combined_df.union(df)
        return combined_df

    def filter_files(
        self, files: DataFrame, existing_file_paths: "Broadcast[list[str]]"
    ) -> DataFrame:
        limit_for_single_dir = int(
            self.file_amount / len(settings.s3_storage.DIRECTORIES)
        )
        filtered_df = files.filter(~files.path.isin(existing_file_paths.value)).limit(
            limit_for_single_dir
        )

        return filtered_df
