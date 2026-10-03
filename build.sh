#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install requirements
pip install -r requirements.txt

# Install the Chromium browser used by VisualAnalyzer.
# Bundle it with the Python package so the deployed Render runtime can find it.
export PLAYWRIGHT_BROWSERS_PATH=0
python -m playwright install --with-deps chromium

# Collect static files
python manage.py collectstatic --noinput

# Run migrations for core (default) database
python manage.py migrate --noinput

# Run migrations for guest_db
python manage.py migrate --database=guest_db --noinput
