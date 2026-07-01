#!/bin/bash
# Deploy to Remote Server

SERVER="SP_AI@192.168.60.27"
PASSWORD="pitch12345"
TARGET_DIR="~/extrack_scammer_worker"

echo "1. Copying files to remote server..."
sshpass -p $PASSWORD ssh -o StrictHostKeyChecking=no $SERVER "mkdir -p $TARGET_DIR"
sshpass -p $PASSWORD scp -o StrictHostKeyChecking=no query_db.py agentic_pipeline.py build_kg_forensics.py requirements.txt Dockerfile .env $SERVER:$TARGET_DIR/

echo "2. Building Docker Image on Remote Server..."
sshpass -p $PASSWORD ssh -o StrictHostKeyChecking=no $SERVER "cd $TARGET_DIR && docker build -t extrack-worker ."

echo "3. Running Docker Container (Network Host to access Ollama and Neo4j)..."
sshpass -p $PASSWORD ssh -o StrictHostKeyChecking=no $SERVER "docker run --rm --network host -v $TARGET_DIR:/app extrack-worker"

echo "4. Copying results back..."
sshpass -p $PASSWORD scp -o StrictHostKeyChecking=no $SERVER:$TARGET_DIR/extracted_v2.json ./extracted_v2_may.json

echo "Done!"
