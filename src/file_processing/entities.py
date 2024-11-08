import io
from dataclasses import dataclass, field

import pefile


@dataclass
class PeFile:
    content: io.BytesIO
    path: str
    pe_handler: pefile.PE = field(init=False)
    architecture: str = field(init=False)
    imports_number: int = field(init=False)
    exports_number: int = field(init=False)
    size: int = field(init=False)

    def __post_init__(self):
        self.pe_handler = pefile.PE(data=self.content.read(), fast_load=True)
        self.architecture = self._get_architecture_type()
        self.imports_number = self._get_imports_number()
        self.exports_number = self._get_exports_number()
        self.size = self._get_size()
        self.file_type = self._get_file_type()

    def _get_architecture_type(self) -> str | None:
        if not hasattr(self.pe_handler, "FILE_HEADER") or not hasattr(
            self.pe_handler.FILE_HEADER, "Machine"
        ):
            return None

        machine_type = self.pe_handler.FILE_HEADER.Machine

        if machine_type == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            return "x64"
        elif machine_type == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_I386"]:
            return "x32"
        else:
            return None

    def _get_imports_number(self) -> int:
        return (
            len(self.pe_handler.DIRECTORY_ENTRY_IMPORT)
            if hasattr(self.pe_handler, "DIRECTORY_ENTRY_IMPORT")
            else 0
        )

    def _get_exports_number(self) -> int:
        return (
            len(self.pe_handler.DIRECTORY_ENTRY_EXPORT.symbols)
            if hasattr(self.pe_handler, "DIRECTORY_ENTRY_EXPORT")
            else 0
        )

    def _get_size(self) -> int:
        return self.content.getbuffer().nbytes

    def _get_file_type(self):
        characteristics = self.pe_handler.FILE_HEADER.Characteristics
        if characteristics & 0x2000:
            return "DLL"
        elif characteristics & 0x0002:
            return "EXE"

        return None

    def get_metadata(self):
        return (
            self.path,
            self.file_type,
            self.architecture,
            self.size,
            self.imports_number,
            self.exports_number,
        )
