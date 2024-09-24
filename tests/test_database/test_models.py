from src.database.models import FileMetadata


def test_get_all_files(session, create_file_metadata):
    result = FileMetadata.get_all_file_paths(session)

    assert len(result) == 5
