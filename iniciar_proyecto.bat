@echo off
echo ===================================================
echo   Iniciando Entorno - TFG Red Teaming AI
echo ===================================================
echo.

echo [1/4] Iniciando Base de Datos SQL Server LocalDB...
sqllocaldb start MSSQLLocalDB

echo [2/4] Iniciando Motor de IA Local (Ollama + WhiteRabbitNeo)...
start "Ollama - WhiteRabbitNeo" cmd /k "ollama run hf.co/bartowski/WhiteRabbitNeo-2.5-Qwen-2.5-Coder-7B-GGUF:latest"

echo [INFO] Esperando 15 segundos para que el modelo cargue...
timeout /t 15 /nobreak > nul

echo [3/4] Iniciando Backend Python (FastAPI + PyRIT)...
start "Backend FastAPI" cmd /k "C:\Users\Sherco\anaconda3\envs\tfg-pyrit\python.exe -m uvicorn 02_api:app --reload --port 8000"


echo.
echo ¡Todos los microservicios han sido lanzados!
pause