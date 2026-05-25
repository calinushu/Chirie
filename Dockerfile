FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATA_DIR=/app/data \
    HOST=0.0.0.0 \
    PORT=8000

WORKDIR /app

COPY app.py /app/app.py
COPY docker-entrypoint.py /app/docker-entrypoint.py
COPY static /app/static

RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /app/data/uploads \
    && chown -R appuser:appuser /app

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/login', timeout=3).read()"

ENTRYPOINT ["python", "/app/docker-entrypoint.py"]
CMD ["python", "app.py"]
