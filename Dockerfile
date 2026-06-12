FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY cve_bot.py .

CMD ["python", "cve_bot.py"]
