import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from src.database.models import (  # Replace with your actual base model
    Base,
    FileMetadata,
)


@pytest.fixture(scope="session")
def session():
    # Create a new SQLite in-memory database
    engine = create_engine("sqlite:///:memory:", echo=False)

    # Create the database tables
    Base.metadata.create_all(engine)

    # Create a session factory bound to the in-memory SQLite database
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

    # Create a new session
    db: Session = SessionLocal()

    yield db  # This will be the database session available for tests

    db.close()  # Clean up after tests
    Base.metadata.drop_all(engine)  # Optionally drop all tables


@pytest.fixture()
def create_file_metadata(session):
    file_metadata_objects = [
        FileMetadata(
            file_path="/path/to/file1.exe",
            size=2048,
            file_type="PE",
            architecture="x86",
            imports=10,
            exports=5,
        ),
        FileMetadata(
            file_path="/path/to/file2.dll",
            size=4096,
            file_type="PE",
            architecture="x64",
            imports=15,
            exports=8,
        ),
        FileMetadata(
            file_path="/path/to/file3.sys",
            size=5120,
            file_type="PE",
            architecture="x86",
            imports=20,
            exports=12,
        ),
        FileMetadata(
            file_path="/path/to/file4.bin",
            size=1024,
            file_type="binary",
            architecture="x64",
            imports=5,
            exports=0,
        ),
        FileMetadata(
            file_path="/path/to/file5.txt",
            size=256,
            file_type="text",
            architecture="N/A",
            imports=0,
            exports=0,
        ),
    ]

    for file_metadata_object in file_metadata_objects:
        file_metadata_object.create(session)
