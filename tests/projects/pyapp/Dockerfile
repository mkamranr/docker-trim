FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y gcc g++ make curl vim git

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY . .

EXPOSE 8000
CMD ["gunicorn", "-b", "0.0.0.0:8000", "app:app"]
