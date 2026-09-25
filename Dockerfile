FROM python:3.11-slim

WORKDIR /app
COPY src/ ./src/
ENV PYTHONPATH=/app/src
CMD ["python", "-c", "import signaldesk_deploy"]
