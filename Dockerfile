FROM python:3.12-slim

# Prevent Python from writing .pyc and buffer stdout/stderr
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install python dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir gunicorn

# Copy application codebase
COPY backend/ /app/backend/
COPY .env.example /app/.env

WORKDIR /app/backend

# Collect static assets
RUN python manage.py collectstatic --noinput

EXPOSE 8000

CMD ["gunicorn", "pulseapi.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3", "--timeout", "120"]
