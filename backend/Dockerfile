FROM python:3.10-slim

ENV PYTHONUNBUFFERED 1
ENV APP_HOME /app
WORKDIR $APP_HOME

# התקנת חבילות מערכת נדרשות:
# 1. libpq-dev/build-essential (להתקנת psycopg2)
# 2. postgresql-client (עבור pg_isready ב-entrypoint.sh)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    postgresql-client && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY password_model.pkl .
COPY generate_model.py .

# קובץ Entrypoint להמתנה ל-DB
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

ENTRYPOINT ["entrypoint.sh"]