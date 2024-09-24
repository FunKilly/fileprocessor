from typing import Literal, Optional

from pydantic import BaseModel, Field, PostgresDsn, computed_field
from pydantic_core import MultiHostUrl
from pydantic_settings import BaseSettings, SettingsConfigDict


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

    ENVIRONMENT: Literal["local", "live"] = "local"

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


settings = Settings()
