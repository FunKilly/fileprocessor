from abc import ABC, abstractmethod

from pyspark.sql import DataFrame


class Storage(ABC):
    @abstractmethod
    def __init__(self, file_amount: int):
        raise NotImplementedError

    @abstractmethod
    def download_files(self, path: str):
        raise NotImplementedError

    @abstractmethod
    def filter_files(self, files: DataFrame, existing_file_paths):
        raise NotImplementedError

    @abstractmethod
    def list_files(self):
        raise NotImplementedError
