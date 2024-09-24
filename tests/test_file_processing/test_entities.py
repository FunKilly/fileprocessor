from io import BytesIO

import pytest
from pefile import PEFormatError

from src.file_processing.entities import (  # Adjust the import according to your structure
    PeFile,
)


@pytest.fixture
def mock_pefile(mocker):
    # Mock the pefile.PE class
    mock_pe = mocker.patch("pefile.PE")

    # Set up the mock to have the expected attributes and methods
    mock_pe.return_value.FILE_HEADER.Machine = 0x8664  # IMAGE_FILE_MACHINE_AMD64
    mock_pe.return_value.DIRECTORY_ENTRY_IMPORT = ["dummy_import"]
    mock_pe.return_value.DIRECTORY_ENTRY_EXPORT.symbols = ["dummy_export"]
    mock_pe.return_value.FILE_HEADER.Characteristics = 0x2000  # DLL

    return mock_pe


def test_pefile_initialization(mock_pefile):
    content = BytesIO(b"MZ" + bytes(64))  # Dummy PE file content
    pe_file = PeFile(content=content, path="dummy_path.exe")

    assert pe_file.architecture == "x64"
    assert pe_file.imports_number == 1
    assert pe_file.exports_number == 1
    assert pe_file.size == 66  # 2 bytes for 'MZ' + 64 bytes of dummy content
    assert pe_file.file_type == "DLL"


def test_pefile_initialization_without_imports(mock_pefile):
    # Modify the mock to have no imports
    mock_pefile.return_value.DIRECTORY_ENTRY_IMPORT = []

    content = BytesIO(b"MZ" + bytes(64))  # Dummy PE file content
    pe_file = PeFile(content=content, path="dummy_path.exe")

    assert pe_file.imports_number == 0


def test_pefile_initialization_without_exports(mock_pefile):
    # Modify the mock to have no exports
    mock_pefile.return_value.DIRECTORY_ENTRY_EXPORT.symbols = []

    content = BytesIO(b"MZ" + bytes(64))  # Dummy PE file content
    pe_file = PeFile(content=content, path="dummy_path.exe")

    assert pe_file.exports_number == 0


def test_pefile_initialization_invalid_machine_type(mock_pefile):
    # Modify the mock to return an invalid machine type
    mock_pefile.return_value.FILE_HEADER.Machine = 0x1234  # Invalid machine type

    content = BytesIO(b"MZ" + bytes(64))  # Dummy PE file content
    pe_file = PeFile(content=content, path="dummy_path.exe")

    assert pe_file.architecture is None


def test_pefile_initialization_invalid_pe_format(mocker):
    # Mock PE to raise PEFormatError
    mocker.patch("pefile.PE", side_effect=PEFormatError("Invalid PE format"))

    content = BytesIO(b"MZ" + bytes(64))  # Dummy PE file content
    with pytest.raises(PEFormatError):
        PeFile(content=content, path="dummy_path.exe")
