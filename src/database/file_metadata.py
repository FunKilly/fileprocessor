from .db import Base
from sqlalchemy import Column, Integer, String, select, DateTime
from sqlalchemy.orm import Session
from datetime import datetime


class FileMetadata(Base):
    __tablename__ = "file_metadata"

    id = Column(Integer, primary_key=True, autoincrement=True)
    file_path = Column(String, nullable=False)
    size = Column(Integer, nullable=False)
    file_type = Column(String)
    architecture = Column(String)
    imports = Column(Integer)
    exports = Column(Integer)
    created_at = Column(DateTime, default=datetime.now())

    @staticmethod
    def get_all_file_paths(db_session):
        query = select(FileMetadata.file_path)
        result = db_session.execute(query).scalars()
        return result.all()

    def create(self, session: Session) -> "FileMetadata":
        session.add(self)
        session.commit()
        return self

    @classmethod
    def bulk_create(
        cls, session: Session, records: list["FileMetadata"]
    ) -> list["FileMetadata"]:
        """
        Inserts a list of FileMetadata records in batch.

        Args:
            session (Session): SQLAlchemy session.
            records (list[FileMetadata]): List of FileMetadata objects to be inserted.
        """
        session.bulk_save_objects(records)
        session.commit()
        return records
