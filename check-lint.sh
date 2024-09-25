#!/bin/bash

# Run isort in check mode
echo "Running isort..."
isort --check-only src tests

if [ $? -ne 0 ]; then
    echo "isort failed. Please sort your imports."
    exit 1
fi

# Run ruff for linting (includes formatting checks)
echo "Running ruff..."
ruff check src tests

if [ $? -ne 0 ]; then
    echo "ruff found issues. Please fix the reported issues."
    exit 1
fi

echo "All checks passed!"
