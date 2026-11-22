@echo off
REM tracefind launcher for Windows: creates a virtual env on first run, then starts the app.
cd /d "%~dp0backend"
if not exist .venv (
  echo Setting up tracefind for the first time...
  py -3 -m venv .venv || python -m venv .venv
  call .venv\Scripts\activate.bat
  python -m pip install --upgrade pip >nul
  pip install -r requirements.txt
) else (
  call .venv\Scripts\activate.bat
)
if exist "%~dp0.env" copy /y "%~dp0.env" .env >nul
python -m tracefind serve %*
