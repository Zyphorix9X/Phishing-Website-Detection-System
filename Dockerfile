FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 appuser

COPY requirements.txt ./requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=appuser:appuser . .
RUN mkdir -p logs reports \
    && chown -R appuser:appuser /app

USER appuser
EXPOSE 5000

CMD ["sh", "-c", "flask --app app:app db upgrade && gunicorn --workers 2 --threads 4 --timeout 60 --bind 0.0.0.0:5000 --access-logfile - --error-logfile - app:app"]
