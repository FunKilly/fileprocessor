from abc import ABC, abstractmethod

from pyspark.sql import DataFrame


class Storage(ABC):
    @abstractmethod
    def __init__(self, config):
        raise NotImplementedError

    @abstractmethod
    def download_files(self, path: str):
        raise NotImplementedError

    @abstractmethod
    def filter_files(self, files: DataFrame):
        raise NotImplementedError

    @abstractmethod
    def list_files(self):
        raise NotImplementedError
