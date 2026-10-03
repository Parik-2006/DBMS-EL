#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install requirements
pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --noinput

# Run migrations for core (default) database
python manage.py migrate --noinput

# Run migrations for guest_db
python manage.py migrate --database=guest_db --noinput
