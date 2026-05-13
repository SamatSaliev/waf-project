FROM python:3.12-slim

WORKDIR /app

# Устанавливаем openssl для генерации сертификата
RUN apt-get update && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

# Генерируем самоподписанный сертификат на 365 дней
RUN mkdir -p /certs && \
    openssl req -x509 -newkey rsa:2048 \
      -keyout /certs/key.pem \
      -out    /certs/cert.pem \
      -days   365 -nodes \
      -subj   "/C=KG/ST=Bishkek/L=Bishkek/O=WAF-Diploma/CN=localhost"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8443

CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8443", \
     "--ssl-keyfile",  "/certs/key.pem", \
     "--ssl-certfile", "/certs/cert.pem"]
