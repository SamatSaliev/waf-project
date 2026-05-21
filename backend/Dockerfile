FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir flask==3.1.0

COPY . .

EXPOSE 5000

CMD ["python", "app.py"]
