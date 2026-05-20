FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONOPTIMIZE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /worker
RUN addgroup --system app && adduser --system --ingroup app app
COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile -r requirements.txt
COPY worker.py .

USER app
CMD ["python", "worker.py"]
