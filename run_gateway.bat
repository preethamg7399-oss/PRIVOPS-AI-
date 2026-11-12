@echo off
echo Starting PRIVOPS FastAPI Gateway...
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
pause

