@echo off
setlocal
cd /d "%~dp0"

where py >nul 2>nul
if %errorlevel%==0 (
    py -3 apply_patch.py
    goto finished
)

where python >nul 2>nul
if %errorlevel%==0 (
    python apply_patch.py
    goto finished
)

echo.
echo ERROR: Python 3 was not found.
echo Install Python 3 from https://www.python.org/downloads/windows/

:finished
echo.
pause

