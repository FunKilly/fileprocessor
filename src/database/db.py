import os

from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine
from sqlalchemy.orm import  sessionmaker
from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    pass


metadata = MetaData()


# Create the table in the database
DATABASE_URL = os.getenv("DATABASE_URL")
URL = "postgresql+psycopg2://user:Test1234!@localhost:5432/processing_db"
engine = create_engine(URL)



def get_db_session():
    Session = sessionmaker(bind=engine)
    return Session()