FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONOPTIMIZE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /email-ingest
RUN addgroup --system app && adduser --system --ingroup app app
COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile -r requirements.txt
COPY app.py .

USER app
EXPOSE 8010
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8010", "--loop", "uvloop", "--http", "httptools"]
