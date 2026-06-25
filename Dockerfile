# ==============================================================================
# Base Python Stage
# ==============================================================================
FROM python:3.11-slim AS base

WORKDIR /app

# Install system dependencies needed for live WHOIS lookup
RUN apt-get update && apt-get install -y \
    whois \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code, configurations, data, and trained model binaries
COPY src/ ./src/
COPY models/ ./models/
COPY app.py .
COPY data/ ./data/

# ==============================================================================
# Backend Stage (FastAPI)
# ==============================================================================
FROM base AS backend
EXPOSE 8000
ENV PORT=8000
CMD ["uvicorn", "src.api:app", "--host", "0.0.0.0", "--port", "8000"]

# ==============================================================================
# Frontend Stage (Streamlit)
# ==============================================================================
FROM base AS frontend
EXPOSE 8501
ENV PORT=8501
CMD ["streamlit", "run", "app.py", "--server.port", "8501", "--server.address", "0.0.0.0", "--server.headless", "true", "--browser.gatherUsageStats", "false"]
