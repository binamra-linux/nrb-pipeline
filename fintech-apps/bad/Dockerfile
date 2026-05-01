# Simulated insecure Nepali fintech app
FROM ubuntu:18.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    ssh \
    net-tools

RUN pip3 install flask==0.12.4 requests==2.18.0

WORKDIR /app

COPY app.py .

# Hardcoded credentials - NRB violation
ENV DB_PASSWORD=supersecret123
ENV API_KEY=nrb-fintech-key-abc123
ENV SECRET_KEY=mysecretkey

# Running as root - NRB violation
USER root

# Unnecessary ports exposed - NRB violation
EXPOSE 22 80 443 8080 3306

CMD ["python3", "app.py"]
