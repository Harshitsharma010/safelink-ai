@echo off
echo.
echo 🔒 SafeLink AI — Setup and Launch
echo ==================================
echo.

where node >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Node.js not found. Install it from https://nodejs.org
    pause
    exit /b 1
)

echo Installing backend dependencies...
cd backend
call npm install --silent
cd ..
echo Backend dependencies installed.

echo.
echo Installing frontend dependencies...
cd frontend
call npm install --silent
cd ..
echo Frontend dependencies installed.

echo.
echo Starting backend on port 3001...
start "SafeLink Backend" cmd /k "cd backend && node server.js"

timeout /t 3 /nobreak >nul

echo Starting frontend on port 3000...
start "SafeLink Frontend" cmd /k "cd frontend && npm start"

echo.
echo ✓ SafeLink AI is launching!
echo   Backend  → http://localhost:3001
echo   Frontend → http://localhost:3000
echo.
echo Both servers are running in separate windows.
echo Close those windows to stop the servers.
pause
