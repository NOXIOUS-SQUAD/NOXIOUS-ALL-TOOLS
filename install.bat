@echo off
cd /d "%~dp0"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
if errorlevel 1 (
    echo.
    echo Error al instalar dependencias.
    echo Verifica que Python este instalado y agregado al PATH.
    pause
    exit /b 1
)

echo.
echo Dependencias instaladas correctamente.
echo Ejecutando la aplicacion...
python main.py
