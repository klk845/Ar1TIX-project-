@echo off
REM Install required Python packages for Ar1TIX bundle (Windows)
python -m pip install --upgrade pip
python -m pip install -r "%~dp0requirements.txt"
pause
