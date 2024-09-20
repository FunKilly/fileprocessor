from sqlalchemy import Table, Column, Integer, String, MetaData
from sqlalchemy import create_engine
import os

metadata = MetaData()

file_metadata = Table(
    'file_metadata', metadata,
    Column('id', Integer, primary_key=True),
    Column('file_path', String),
    Column('size', Integer),
    Column('file_type', String),
    Column('architecture', String),
    Column('imports', Integer),
    Column('exports', Integer),
)

# Create the table in the database
DATABASE_URL = os.getenv('DATABASE_URL')
engine = create_engine(DATABASE_URL)
metadata.create_all(engine)