FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cve_bot.py .

# Непривилегированный пользователь + каталог для seen_cves.json (персистится через volume)
RUN useradd -m bot && mkdir -p /data && chown bot:bot /data
USER bot
ENV SEEN_FILE=/data/seen_cves.json

CMD ["python", "cve_bot.py"]
