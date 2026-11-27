@echo off
setlocal
cd /d "%~dp0"
if not exist ".venv\Scripts\python.exe" (
    python -m venv .venv
    if errorlevel 1 goto failed
)
".venv\Scripts\python.exe" -m pip install --disable-pip-version-check -r requirements.txt
if errorlevel 1 goto failed
echo Setup complete. Vivaldi must be installed. Run start.bat.
pause
exit /b 0
:failed
echo Setup failed. Python 3.10+ and Internet access are required.
pause
exit /b 1
