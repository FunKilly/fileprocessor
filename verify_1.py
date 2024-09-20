import sys

import pefile
import os

def extract_metadata(file_path):
    # Implement metadata extraction logic here
    pe = pefile.PE(file_path)
    return {
        "file_path": file_path,
        "size": os.path.getsize(file_path),
        "file_type": "exe" if file_path.endswith(".exe") else "dll",
        "architecture": "x64" if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64'] else "x86",
        "imports": len(pe.DIRECTORY_ENTRY_IMPORT),
        "exports": len(pe.DIRECTORY_ENTRY_EXPORT.symbols) if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0
    }


if __name__ == "__main__":
    extract_metadata(sys.argv[1])