#!/bin/bash

# Check if a number of files argument is provided
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <number_of_files>"
    exit 1
fi

NUMBER_OF_FILES=$1

# Run alembic migrations
alembic upgrade head

# Run the Python application with the specified number of files
/opt/pysetup/.venv/bin/python -m src.main "$NUMBER_OF_FILES"