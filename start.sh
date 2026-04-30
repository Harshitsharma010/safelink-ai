#!/bin/bash

# SafeLink AI — One-command setup & launch
# Run: chmod +x start.sh && ./start.sh

echo ""
echo "🔒 SafeLink AI — Setup & Launch"
echo "================================"
echo ""

# Check Node.js
if ! command -v node &> /dev/null; then
  echo "❌ Node.js not found. Install it from https://nodejs.org (v18+)"
  exit 1
fi

NODE_VER=$(node -v | cut -d'v' -f2 | cut -d'.' -f1)
echo "✓ Node.js $(node -v) detected"

# Install backend deps
echo ""
echo "📦 Installing backend dependencies..."
cd backend && npm install --silent && cd ..
echo "✓ Backend ready"

# Install frontend deps
echo ""
echo "📦 Installing frontend dependencies..."
cd frontend && npm install --silent && cd ..
echo "✓ Frontend ready"

# Launch both
echo ""
echo "🚀 Starting SafeLink AI..."
echo "   Backend  → http://localhost:3001"
echo "   Frontend → http://localhost:3000"
echo ""
echo "Press Ctrl+C to stop both servers."
echo ""

# Start backend in background
cd backend && node server.js &
BACKEND_PID=$!
cd ..

# Wait a moment then start frontend
sleep 2
cd frontend && npm start &
FRONTEND_PID=$!
cd ..

# Handle Ctrl+C — kill both
trap "echo ''; echo 'Shutting down...'; kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit 0" INT TERM

wait
