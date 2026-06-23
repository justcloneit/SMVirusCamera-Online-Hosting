FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY SMVirusCamera.py .
COPY app.py .
COPY telegram_config.json .
COPY credentials.txt .

ENV PORT=5000
ENV PYTHONUNBUFFERED=1

EXPOSE 5000

CMD ["python", "app.py"]
