FROM python:3.13-alpine
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY recovery.py app.py ./
RUN addgroup -S -g 1000 watcher && adduser -S -u 1000 -G watcher watcher \
    && mkdir -p /var/lib/fleet-recovery \
    && chown -R watcher:watcher /var/lib/fleet-recovery /app
USER watcher
CMD ["python", "-u", "app.py"]
