#!/usr/bin/env bash
# Exit on error
set -o errexit

# Install requirements
pip install -r requirements.txt

# Install the Chromium browser used by VisualAnalyzer.
# Render's native Python build image does not allow Playwright to switch to root
# for --with-deps, so install the browser binary without OS package installation.
# The Render image supplies the runtime libraries needed by Chromium.
export PLAYWRIGHT_BROWSERS_PATH=0
python -m playwright install chromium

# Collect static files
python manage.py collectstatic --noinput

# Run migrations for core (default) database
python manage.py migrate --noinput

# Run migrations for guest_db
python manage.py migrate --database=guest_db --noinput
