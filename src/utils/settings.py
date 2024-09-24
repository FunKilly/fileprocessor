from typing import Optional

from pydantic import Field, PostgresDsn, computed_field, field_validator
from pydantic_core import MultiHostUrl
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.file_storage.entities import FileSourceEnum
from src.utils.entities import EnvironmentEnum


class S3StorageSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_ignore_empty=True, extra="ignore", env_prefix="S3_STORAGE_"
    )

    BUCKET_NAME: str | None
    DIRECTORIES: list[str | int] | None


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_ignore_empty=True, extra="ignore"
    )

    ENVIRONMENT: EnvironmentEnum = EnvironmentEnum.LOCAL
    FILE_SOURCE: FileSourceEnum = FileSourceEnum.S3

    POSTGRES_SERVER: str = "db"
    POSTGRES_PORT: int = 5432
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "processing_db"

    SPARK_WORKER_MEMORY: str = "5G"
    SPARK_WORKER_CORES: int = 6

    @computed_field  # type: ignore[prop-decorator]
    @property
    def SQLALCHEMY_DATABASE_URI(self) -> PostgresDsn:
        return MultiHostUrl.build(
            scheme="postgresql+psycopg2",
            username=self.POSTGRES_USER,
            password=self.POSTGRES_PASSWORD,
            host=self.POSTGRES_SERVER,
            port=self.POSTGRES_PORT,
            path=self.POSTGRES_DB,
        )

    s3_storage: Optional[S3StorageSettings] = Field(
        description="S3 storage settings", default_factory=S3StorageSettings
    )

    @classmethod
    @field_validator("ENVIRONMENT")
    def validate_environment(cls, value):
        # Normalize to upper case to match Enum
        if isinstance(value, str):
            value = value.upper()
        if value not in EnvironmentEnum.__members__:
            raise ValueError(
                f"Invalid environment: {value}. Must be one of {list(EnvironmentEnum)}"
            )
        return EnvironmentEnum[value]

    @classmethod
    @field_validator("FILE_SOURCE")
    def validate_environment(cls, value):
        # Normalize to upper case to match Enum
        if isinstance(value, str):
            value = value.upper()
        if value not in FileSourceEnum.__members__:
            raise ValueError(
                f"Invalid environment: {value}. Must be one of {list(FileSourceEnum)}"
            )
        return FileSourceEnum[value]


settings = Settings()
