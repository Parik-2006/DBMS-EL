@echo off
echo Starting MaliciousBot System...
echo Branch: nikhil
echo.

:: Start the Django development server in a new window
start "MaliciousBot Backend" cmd /k ".\.venv_canonical\Scripts\python.exe manage.py runserver"

echo Waiting for server to initialize...
timeout /t 5 /nobreak > nul

:: Open the application in Chrome
echo Opening Chrome...
start chrome "http://127.0.0.1:8000"

echo.
echo System is running. Close the backend terminal to stop.
pause
