@echo off
setlocal
cd /d "%~dp0.."

set "PYTHON=.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
    echo Ambiente virtual nao encontrado: %PYTHON%
    echo Crie-o na raiz do projeto com: python -m venv .venv
    exit /b 1
)

set "PYTHONPATH=%CD%\src"
"%PYTHON%" -m sarr_core --run-sim
exit /b %ERRORLEVEL%
