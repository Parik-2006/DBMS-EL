@echo off
chcp 65001 >nul
echo ============================================================
echo  MaliciousBot - Malicious URL Detection System
echo  Nikhil Fallback Architecture - Branch: nikhil
echo ============================================================
echo.

:: Check if virtual environment exists
if not exist ".venv_canonical\Scripts\python.exe" (
    echo ERROR: Virtual environment not found!
    echo Please run: pip install -r requirements.txt
    pause
    exit /b 1
)

echo [1/3] Starting Django development server...
start "MaliciousBot Server" cmd /k ".\.venv_canonical\Scripts\python.exe manage.py runserver 0.0.0.0:8000"

echo [2/3] Waiting for server to initialize (5 seconds)...
timeout /t 5 /nobreak > nul

echo [3/3] Opening application in browser...
start chrome "http://127.0.0.1:8000" 2>nul
if errorlevel 1 start "MaliciousBot" cmd /k "echo Opening Chrome failed. Please navigate to http://127.0.0.1:8000 manually.&&pause"

echo.
echo ============================================================
echo  SUCCESS: Application is running!
echo ============================================================
echo.
echo  Access the application at: http://127.0.0.1:8000
echo  API Endpoints:
echo    - POST /api/fallback/result/
echo    - GET  /api/fallback/uncertain-scans/
echo    - GET  /api/fallback/scan-status/<id>/
echo    - POST /api/nikhil/submit-review/
echo.
echo  To stop: Close the "MaliciousBot Server" window.
echo ============================================================
pause