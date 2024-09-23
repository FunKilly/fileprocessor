import os

from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


metadata = MetaData()


# Create the table in the database


def get_db_url():
    # TODO DATABASE_URL = os.getenv("DATABASE_URL")
    return "postgresql+psycopg2://user:Test1234!@localhost:5432/processing_db"


engine = create_engine(get_db_url())


def get_db_session():
    Session = sessionmaker(bind=engine)
    return Session()
