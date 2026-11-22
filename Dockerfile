FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py legal.py i18n_html.py landing.py ./
COPY i18n/en-html.json ./i18n/
COPY static ./static
RUN useradd -u 1000 -m app && mkdir -p /data && chown app /data
USER app
ENV DB_PATH=/data/kopfwetter-app.db PYTHONDONTWRITEBYTECODE=1
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8000/healthz')" || exit 1
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*", "--no-server-header", "--no-access-log"]
