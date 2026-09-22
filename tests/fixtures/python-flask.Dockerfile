FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc g++ curl vim netcat-openbsd libpq-dev

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

ENV PYTHONUNBUFFERED=1
EXPOSE 8000

CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
