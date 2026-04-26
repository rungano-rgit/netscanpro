FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    FLASK_ENV=production \
    SCANNER_DB=/app/scanner.db \
    SCANNER_LOG=/app/audit.log

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./

EXPOSE 5000

CMD ["gunicorn", "wsgi:app", "--bind", "0.0.0.0:5000", "--workers", "3"]
