import os

from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from src.utils.settings import settings


class Base(DeclarativeBase):
    pass


metadata = MetaData()


# Create the table in the database


def get_db_url():
    return str(settings.SQLALCHEMY_DATABASE_URI)


engine = create_engine(get_db_url())


def get_db_session():
    Session = sessionmaker(bind=engine)
    return Session()
