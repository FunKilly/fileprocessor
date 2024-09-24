from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, select
from sqlalchemy.orm import Session

from .utils import Base


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
    def get_all_file_paths(db_session: Session) -> list[str]:
        query = select(FileMetadata.file_path)
        result = db_session.scalars(query).all()
        return result

    def create(self, session: Session) -> "FileMetadata":
        session.add(self)
        session.commit()
        return self
