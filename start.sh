#!/usr/bin/env bash
PORT="${PORT:-8501}"
exec streamlit run frontend/dashboard.py --server.port "$PORT" --server.address 0.0.0.0 --server.headless true
