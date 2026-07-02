FROM python:3.11-slim

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default worker entrypoint. Dashboard and compose jobs override this when needed.
CMD ["python", "agentic_pipeline.py"]
