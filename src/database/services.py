from pyspark.sql import DataFrame

from src.utils.settings import settings


def add_metadata_to_database(metadeta_df: DataFrame) -> None:
    postgres_url = f"jdbc:postgresql://{settings.POSTGRES_SERVER}:{settings.POSTGRES_PORT}/{settings.POSTGRES_DB}"

    table_name = "file_metadata"
    properties = {
        "user": settings.POSTGRES_USER,
        "password": settings.POSTGRES_PASSWORD,
        "driver": "org.postgresql.Driver",
    }
    metadeta_df.write.jdbc(
        url=postgres_url, table=table_name, mode="append", properties=properties
    )
