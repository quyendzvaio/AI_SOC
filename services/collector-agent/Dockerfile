FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONOPTIMIZE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /agent
COPY requirements.txt .
RUN pip install --no-cache-dir --no-compile -r requirements.txt
COPY agent.py .

CMD ["python", "agent.py"]
