from sqlalchemy import MetaData, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from src.utils.settings import settings


class Base(DeclarativeBase):
    pass


metadata = MetaData()


def get_db_url() -> str:
    return str(settings.SQLALCHEMY_DATABASE_URI)


engine = create_engine(get_db_url())


def get_db_session() -> Session:
    Session = sessionmaker(bind=engine)
    return Session()
