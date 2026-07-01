FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# First fetch data, then run pipeline, then build KG
CMD ["sh", "-c", "python query_db.py && python agentic_pipeline.py && python build_kg_forensics.py"]
