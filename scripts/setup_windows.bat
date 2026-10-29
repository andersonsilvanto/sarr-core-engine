@echo off
setlocal
cd /d "%~dp0.."

set "PYTHON=.venv\Scripts\python.exe"
if not exist "%PYTHON%" (
    echo Ambiente virtual nao encontrado: %PYTHON%
    echo Crie-o na raiz do projeto com um CPython x64 entre 3.10 e 3.15:
    echo py -3.15 -m venv .venv
    exit /b 1
)

"%PYTHON%" -c "import struct,sys; raise SystemExit(0 if sys.platform == 'win32' and struct.calcsize('P') == 8 and (3,10) <= sys.version_info[:2] < (3,16) else 1)"
if errorlevel 1 (
    echo Use CPython x64 entre 3.10 e 3.15 para esta configuracao de release.
    exit /b 1
)

"%PYTHON%" -m pip install --require-hashes -r requirements-lock.txt
if errorlevel 1 exit /b 1

"%PYTHON%" -m pip install --no-deps --no-build-isolation -e .
if errorlevel 1 exit /b 1

set "PYTHONPATH=%CD%\src"
"%PYTHON%" -m unittest discover -s tests -p "*test*.py" -v
exit /b %ERRORLEVEL%
